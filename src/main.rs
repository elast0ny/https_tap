use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::Waker;
use mio::{Events, Interest, Poll, Registry, Token};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use env_logger::Env;
use log::*;
use structopt::StructOpt;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

type Result<T> = std::result::Result<T, std::boxed::Box<dyn std::error::Error>>;

struct Client {
    tls: Box<dyn rustls::Session>,
    socket: mio::net::TcpStream,
    peer_id: usize,
    remote_recv: Vec<u8>,
    is_loopback: bool,
    loopback_id: usize,
}

#[derive(Debug, StructOpt)]
struct Args {
    /// Path to the certificate chain
    #[structopt(short, long)]
    cert: PathBuf,
    /// Path to the private key file
    #[structopt(short, long)]
    key: PathBuf,
    /// The IP of the interface to bind to
    #[structopt(short, long, default_value = "0.0.0.0")]
    bind: String,
    /// Port to listen on and forward to
    #[structopt(short, long, default_value = "443")]
    port: u16,
    /// Where to replay the plaintext traffic
    #[structopt(short, long, default_value = "127.0.0.1:4433")]
    loopback: String,
}

struct Ctx {
    connections: HashMap<Token, Client>,
    remote_port: u16,
    loopback_addr: String,
    unique_id: usize,
    loopback_id_queue: VecDeque<usize>,
    resolver: Resolver,
}

const SERVER: usize = 0;
const LOOPBACK: usize = 1;

fn main() -> Result<()> {
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::from_args();

    let ssl_ctx = load_ssl_config(&args)?;

    info!("Binding to {}:{}", args.bind, args.port);

    // Setup the TCP server socket.
    let addr = format!("{}:{}", args.bind, args.port).parse().unwrap();
    let mut listener = TcpListener::bind(addr)?;
    let mut loopback = TcpListener::bind(args.loopback.parse()?)?;
    // Create a poll instance.
    let mut poll = Poll::new()?;
    // Create storage for events.
    let mut events = Events::with_capacity(128);
    poll.registry()
        .register(&mut listener, Token(SERVER), Interest::READABLE)?;
    poll.registry()
        .register(&mut loopback, Token(LOOPBACK), Interest::READABLE)?;
    info!("Waiting for connections !");
    let mut res_opts = ResolverOpts::default();
    res_opts.use_hosts_file = false;

    let mut ctx = Ctx {
        remote_port: args.port,
        connections: HashMap::new(),
        loopback_addr: args.loopback,
        unique_id: LOOPBACK,
        loopback_id_queue: VecDeque::new(),
        resolver: Resolver::new(ResolverConfig::google(), res_opts).unwrap(),
    };

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token().0 {
                SERVER | LOOPBACK => loop {
                    let is_loopback = event.token().0 == LOOPBACK;
                    let listener_sock = if is_loopback {
                        &mut loopback
                    } else {
                        &mut listener
                    };

                    let (mut socket, _address) = match listener_sock.accept() {
                        Ok((socket, address)) => (socket, address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            error!("Accept error : {}", e);
                            continue;
                        }
                    };
                    let id = Token(if is_loopback {
                        ctx.loopback_id_queue.pop_front().unwrap()
                    } else {
                        ctx.unique_id += 1;
                        ctx.unique_id
                    });

                    debug!("Accept peer {}", id.0);

                    poll.registry().register(
                        &mut socket,
                        id,
                        if is_loopback {
                            Interest::READABLE
                        } else {
                            Interest::READABLE.add(Interest::WRITABLE)
                        },
                    )?;

                    ctx.connections.insert(
                        id,
                        Client {
                            tls: Box::new(rustls::ServerSession::new(&ssl_ctx)),
                            socket,
                            peer_id: 0,
                            is_loopback,
                            loopback_id: 0,
                            remote_recv: Vec::with_capacity(1024),
                        },
                    );
                },
                cli_id => {
                    if let Err(_e) = handle_client(poll.registry(), event, &mut ctx) {
                        let mut peer_id = 0;
                        if let Some(mut cli) = ctx.connections.remove(&Token(cli_id)) {
                            let _ = poll.registry().deregister(&mut cli.socket);
                            if !cli.is_loopback {
                                //warn!("[{}] Error, closing connection : {}", cli_id, e);
                                peer_id = cli.peer_id;
                                cli.tls.send_close_notify();
                                let _ = cli.tls.write_tls(&mut cli.socket);
                            }
                            let _ = cli.socket.shutdown(std::net::Shutdown::Both);
                        }
                        if peer_id != 0 {
                            if let Some(mut cli) = ctx.connections.remove(&Token(peer_id)) {
                                let _ = poll.registry().deregister(&mut cli.socket);
                                if !cli.is_loopback {
                                    //warn!("Also closing connected peer {}", peer_id);
                                    cli.tls.send_close_notify();
                                    let _ = cli.tls.write_tls(&mut cli.socket);
                                }
                                let _ = cli.socket.shutdown(std::net::Shutdown::Both);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn load_ssl_config(args: &Args) -> Result<Arc<rustls::ServerConfig>> {
    if !args.cert.is_file() || !args.key.is_file() {
        error!("Cert or key path does not exist !");
        return Err(From::from("TLS init failed"));
    }
    info!("Loading certs & key");
    // Read in the cert files
    let mut cert_buf = BufReader::new(File::open(&args.cert)?);
    let mut key_buf = BufReader::new(File::open(&args.key)?);
    let certs = match rustls::internal::pemfile::certs(&mut cert_buf) {
        Ok(c) => c,
        Err(_) => {
            error!("Failed to parse certificate");
            return Err(From::from("TLS init failed"));
        }
    };
    let key = match rustls::internal::pemfile::rsa_private_keys(&mut key_buf) {
        Ok(mut c) => {
            if c.len() != 1 {
                error!("Key file must contain one cert");
                return Err(From::from("TLS init failed"));
            }
            c.pop().unwrap()
        }
        Err(_) => {
            error!("Failed to parse key");
            return Err(From::from("TLS init failed"));
        }
    };
    let mut ssl_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    if let Err(e) = ssl_config.set_single_cert(certs, key) {
        error!("{}", e);
        return Err(From::from("TLS init failed"));
    }

    Ok(Arc::new(ssl_config))
}

fn handle_client(registry: &Registry, event: &Event, ctx: &mut Ctx) -> Result<()> {
    let cli_id = &event.token();
    let cli = match ctx.connections.get_mut(cli_id) {
        Some(c) => c,
        None => return Err(From::from(format!("Unknown client {}", cli_id.0))),
    };

    if cli.is_loopback {
        return handle_loopback(cli, event);
    }

    let forward_id;
    let loopback_id;
    let mut forward_data = Vec::new();

    // Append data to plaintext buffer
    if !cli.tls.is_handshaking() && !cli.remote_recv.is_empty() {
        if let Err(e) = cli.tls.write_all(&cli.remote_recv) {
            return Err(From::from(format!("TLS encrypt failed : {}", e)));
        }
        cli.remote_recv.clear();
    }

    while cli.tls.wants_write() {
        match cli.tls.write_tls(&mut cli.socket) {
            Ok(_n) => debug!("[{}] Sent {}", cli_id.0, _n),
            Err(ref err) if would_block(err) => break,
            Err(ref err) if interrupted(err) => continue,
            Err(e) => {
                return Err(From::from(format!("Failed to write to socket : {}", e)));
            }
        };
    }

    if event.is_readable() {
        while cli.tls.wants_read() {
            match cli.tls.read_tls(&mut cli.socket) {
                Ok(0) => {
                    return Err(From::from(format!(
                        "[{}] Failed to read from socket : read_tls returned 0",
                        cli_id.0
                    )));
                }
                Ok(_n) => {}
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                // Other errors we'll consider fatal.
                Err(e) => {
                    return Err(From::from(format!(
                        "{} Failed to recv from client : {}",
                        cli_id.0, e
                    )));
                }
            }
        }

        // Decrypt packets
        if let Err(e) = cli.tls.process_new_packets() {
            return Err(From::from(format!("TLS decrypt failed : {}", e)));
        }
        // Get decrypted plaintext
        if let Err(e) = cli.tls.read_to_end(&mut forward_data) {
            return Err(From::from(format!(
                "[{}] Failed to read plaintext packets : {}",
                cli_id.0, e
            )));
        }

        if forward_data.is_empty() {
            return Ok(());
        }
        // New connection
        if cli.peer_id == 0 {
            //Extract target domain
            let data_str = unsafe { std::str::from_utf8_unchecked(&forward_data) };
            let mut domain = None;
            if let Some(mut idx_start) = data_str.find("Host: ") {
                idx_start += "Host: ".len();
                if let Some(idx_end) = data_str[idx_start..].find("\r\n") {
                    domain = Some(&data_str[idx_start..idx_start + idx_end]);
                }
            }
            if domain.is_none() {
                return Err(From::from(
                    "Failed to extract target host from received request...",
                ));
            }
            let domain = domain.unwrap();
            let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();

            // Lookup the IP addresses associated with a name.
            let response = ctx.resolver.lookup_ip(domain).unwrap();
            let address = match response.iter().next() {
                Some(a) if a.is_ipv4() => a.to_string(),
                Some(a) if a.is_ipv6() => a.to_string(),
                _ => {
                    return Err(From::from(format!(
                        "Unable to resolve IP for host : {}",
                        domain
                    )))
                }
            };

            // Create SSL context
            let mut config = rustls::ClientConfig::new();
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            let config = Arc::new(config);

            //Connect to plaintext loopback
            info!("Connecting to loopback");
            let mut loopback_sock = match TcpStream::connect(ctx.loopback_addr.parse()?) {
                Ok(s) => s,
                Err(e) => return Err(From::from(format!("Failed to connect to loopback : {}", e))),
            };
            ctx.unique_id += 1;
            loopback_id = ctx.unique_id;
            ctx.unique_id += 1;
            let peer_loopback_id = ctx.unique_id;
            ctx.loopback_id_queue.push_back(peer_loopback_id);
            registry.register(&mut loopback_sock, Token(loopback_id), Interest::READABLE)?;
            cli.loopback_id = loopback_id;
            ctx.connections.insert(
                Token(loopback_id),
                Client {
                    tls: Box::new(rustls::ClientSession::new(&config, dns_name)),
                    socket: loopback_sock,
                    is_loopback: true,
                    loopback_id: 0,
                    peer_id: cli_id.0,
                    remote_recv: Vec::with_capacity(1024),
                },
            );
            // Connect to real domain
            info!("Connecting to {} ({}:{})", domain, address, ctx.remote_port);
            let mut peer_sock =
                match TcpStream::connect(format!("{}:{}", address, ctx.remote_port).parse()?) {
                    Ok(s) => s,
                    Err(e) => return Err(From::from(format!("Failed to connect to peer : {}", e))),
                };
            ctx.unique_id += 1;
            forward_id = ctx.unique_id;
            debug!("[{}] New peer {}", cli_id.0, forward_id);
            registry.register(
                &mut peer_sock,
                Token(forward_id),
                Interest::READABLE.add(Interest::WRITABLE),
            )?;
            ctx.connections.insert(
                Token(forward_id),
                Client {
                    tls: Box::new(rustls::ClientSession::new(&config, dns_name)),
                    socket: peer_sock,
                    is_loopback: false,
                    loopback_id: peer_loopback_id,
                    peer_id: cli_id.0,
                    remote_recv: Vec::with_capacity(1024),
                },
            );

            print_ascii(&forward_data);
        } else {
            loopback_id = cli.loopback_id;
            forward_id = cli.peer_id;
        }

        //Forward to loopback
        if let Some(peer) = ctx.connections.get_mut(&Token(loopback_id)) {
            debug!("Forwarding to loopback {}", loopback_id);
            peer.remote_recv.extend(&forward_data);
            let waker = Waker::new(registry, Token(loopback_id))?;
            waker.wake()?;
        }

        //Forward to remote peer
        if let Some(peer) = ctx.connections.get_mut(&Token(forward_id)) {
            debug!("Forwarding to peer {}", forward_id);
            peer.remote_recv.extend(&forward_data);
            let waker = Waker::new(registry, Token(forward_id))?;
            waker.wake()?;
        }
    }

    Ok(())
}

fn handle_loopback(cli: &mut Client, event: &Event) -> Result<()> {
    if !cli.remote_recv.is_empty() {
        loop {
            match cli.socket.write_all(&cli.remote_recv) {
                Ok(_n) => break,
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                Err(e) => {
                    return Err(From::from(format!("Failed to write to socket : {}", e)));
                }
            };
        }
        cli.remote_recv.clear();
    }

    // Simply flush the recv buffer
    if event.is_readable() {
        // We can (maybe) read from the connection.
        loop {
            let mut buf = [0; 256];
            match cli.socket.read(&mut buf) {
                Ok(0) => break,
                Ok(_n) => continue,
                // Would block "errors" are the OS's way of saying that the
                // connection is not actually ready to perform this I/O operation.
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                // Other errors we'll consider fatal.
                Err(err) => return Err(From::from(format!("loopback recv error : {}", err))),
            }
        }
    }

    Ok(())
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

fn print_ascii(bytes: &[u8]) {
    let mut res = String::with_capacity(bytes.len());
    for b in bytes {
        let ch = *b as char;

        if ch.is_ascii() {
            res.push(ch);
        } else {
            res.push('?');
        }
    }
    println!("\n\t{}", res);
}
