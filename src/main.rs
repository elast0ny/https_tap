use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::Waker;
use mio::{Events, Interest, Poll, Registry, Token};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use env_logger::Env;
use log::*;
use native_tls::{MidHandshakeTlsStream, TlsAcceptor, TlsConnector, TlsStream};
use structopt::StructOpt;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;
type Result<T> = std::result::Result<T, std::boxed::Box<dyn std::error::Error>>;

struct Peer {
    plain_sock: Option<TcpStream>,
    mid_handshake_sock: Option<MidHandshakeTlsStream<TcpStream>>,
    tls_sock: Option<TlsStream<TcpStream>>,
    is_loopback: bool,
    forward_domain: Option<String>,
    /// Contains the TLS session info if present
    /// tls: Option<Box<dyn rustls::Session>>,
    /// Id of the peer to forward the recv'ed data to
    forward_id: Option<usize>,
    /// Id of the loopback peer to forward decrypted traffic
    loopback_id: Option<usize>,
    /// Buffer containing data that has been received from this peer's remote endpoint
    forward_buf: Vec<u8>,
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
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    connections: HashMap<Token, Peer>,
    remote_port: u16,
    loopback_addr: String,
    unique_id: usize,
    loopback_id_queue: VecDeque<usize>,
    resolver: Resolver,
}
impl Ctx {
    pub fn add_peer(&mut self, mut new_peer: Peer, registry: &Registry) -> Result<usize> {
        let id = if new_peer.is_loopback {
            if new_peer.forward_id.is_none() {
                self.loopback_id_queue.pop_front().unwrap()
            } else {
                self.unique_id += 1;
                self.loopback_id_queue.push_back(self.unique_id);
                self.unique_id += 1;
                self.unique_id
            }
        } else {
            self.unique_id += 1;
            self.unique_id
        };
        debug!(
            "New peer {} {}",
            id,
            if new_peer.is_loopback {
                "(Loopback)"
            } else {
                ""
            }
        );
        registry.register(
            new_peer.plain_sock.as_mut().unwrap(),
            Token(id),
            Interest::READABLE.add(Interest::WRITABLE),
        )?;

        // Add peer to our list of connections
        self.connections.insert(Token(id), new_peer);

        Ok(id)
    }
}

const SERVER: usize = 0;
const LOOPBACK: usize = 1;

fn main() -> Result<()> {
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::from_args();

    info!("Binding to {}:{}", args.bind, args.port);

    // Read in certificates
    let mut file = File::open("certs/suenorth.pfx").unwrap();
    let mut file_bytes = vec![];
    file.read_to_end(&mut file_bytes)?;
    let acceptor =
        native_tls::TlsAcceptor::new(native_tls::Identity::from_pkcs12(&file_bytes, "letmein")?)?;

    // Setup the server sockets
    let addr = format!("{}:{}", args.bind, args.port).parse().unwrap();
    let mut proxy_sock = TcpListener::bind(addr)?;
    let mut loopback_sock = TcpListener::bind(args.loopback.parse()?)?;
    // Create a poll instance.
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    poll.registry()
        .register(&mut proxy_sock, Token(SERVER), Interest::READABLE)?;
    poll.registry()
        .register(&mut loopback_sock, Token(LOOPBACK), Interest::READABLE)?;
    info!("Waiting for connections !");
    let mut res_opts = ResolverOpts::default();
    res_opts.use_hosts_file = false;

    let mut ctx = Ctx {
        acceptor,
        connector: TlsConnector::new().unwrap(),
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
                    let (is_loopback, listen_sock) = if event.token().0 == LOOPBACK {
                        (true, &mut loopback_sock)
                    } else {
                        (false, &mut proxy_sock)
                    };

                    // Accept connection
                    let (socket, _address) = match listen_sock.accept() {
                        Ok((socket, address)) => (socket, address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            error!("Accept error : {}", e);
                            continue;
                        }
                    };

                    let peer = Peer {
                        plain_sock: Some(socket),
                        mid_handshake_sock: None,
                        tls_sock: None,
                        is_loopback,
                        forward_domain: None,
                        forward_id: None,
                        loopback_id: None,
                        forward_buf: Vec::with_capacity(1024),
                    };

                    let peer_id = ctx.add_peer(peer, poll.registry())?;
                    debug!("Accepted peer {}", peer_id);
                },
                cli_id => {
                    if let Err(_e) = handle_client(poll.registry(), event, &mut ctx) {
                        error!("{}", _e);
                        cleanup_peer(cli_id, poll.registry(), &mut ctx);
                    }
                }
            }
        }
    }
}

fn handle_client(registry: &Registry, event: &Event, ctx: &mut Ctx) -> Result<()> {
    let cli_id = &event.token();
    let peer = match ctx.connections.get_mut(cli_id) {
        Some(c) => c,
        None => {
            //warn!("Unknown client {}", cli_id.0);
            cleanup_peer(cli_id.0, registry, ctx);
            return Ok(());
        }
    };

    if peer.is_loopback {
        return handle_loopback(peer, event);
    }

    // Get the tls socket
    let sock = match peer.tls_sock {
        Some(ref mut s) => s,
        None => {
            // Advance the handshake state
            match if let Some(s) = peer.plain_sock.take() {
                if let Some(ref domain) = peer.forward_domain {
                    // Do not send TLS handshake to quick before the non-blocking TCP connect finishes
                    if event.is_writable() || event.is_readable() {
                        ctx.connector.connect(domain, s)
                    } else {
                        return Ok(());
                    }
                } else {
                    ctx.acceptor.accept(s)
                }
            } else if let Some(s) = peer.mid_handshake_sock.take() {
                s.handshake()
            } else {
                return Err(From::from("Invalid state"));
            } {
                Ok(s) => {
                    info!("[{}] TLS handshake successful", cli_id.0);
                    peer.tls_sock = Some(s);
                    peer.tls_sock.as_mut().unwrap()
                }
                Err(native_tls::HandshakeError::WouldBlock(s)) => {
                    peer.mid_handshake_sock = Some(s);
                    return Ok(());
                }
                Err(_e) => {
                    //warn!("[{}] TLS handshake failed : {}", cli_id.0, e);
                    cleanup_peer(cli_id.0, registry, ctx);
                    return Ok(());
                }
            }
        }
    };

    // Rececive available data
    let mut forward_data = Vec::new();
    if event.is_readable() {
        loop {
            match sock.read_to_end(&mut forward_data) {
                Ok(0) => {
                    //warn!("[{}] Failed to read from socket : tls_read returned 0",cli_id.0);
                    cleanup_peer(cli_id.0, registry, ctx);
                    return Ok(());
                }
                Ok(_n) => debug!("[{}] tls_read {}", cli_id.0, _n),
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                // Other errors we'll consider fatal.
                Err(e) => {
                    return Err(From::from(format!(
                        "[{}] Failed to recv from client : {}",
                        cli_id.0, e
                    )));
                }
            }
        }
    }

    // Send forwarded data
    if event.is_writable() && !peer.forward_buf.is_empty() {
        match sock.write_all(&peer.forward_buf) {
            Ok(_) => {
                peer.forward_buf.clear();
            }
            Err(ref err) if would_block(err) => {}
            Err(e) => return Err(From::from(format!("Failed to tls_write : {}", e))),
        };
    }

    // Check if we have received any data to forward through the proxy
    if forward_data.is_empty() {
        return Ok(());
    }

    // If our forwarders havent been created yet
    if peer.forward_id.is_none() {
        //Extract host from http request
        let data_str = unsafe { std::str::from_utf8_unchecked(&forward_data) };
        let mut domain = None;
        if let Some(mut idx_start) = data_str.find("Host: ") {
            idx_start += "Host: ".len();
            if let Some(idx_end) = data_str[idx_start..].find("\r\n") {
                domain = Some(&data_str[idx_start..idx_start + idx_end]);
            }
        }
        let domain = match domain {
            None => {
                return Err(From::from(
                    "Failed to extract target host from received request...",
                ))
            }
            Some(d) => d,
        };

        let address;
        if domain == "suenorth.ca" {
            address = String::from("192.168.2.222");
        } else {
            // Lookup the IP addresses associated with a name.
            let response = ctx.resolver.lookup_ip(domain).unwrap();
            address = match response.iter().next() {
                Some(a) if a.is_ipv4() => a.to_string(),
                Some(a) if a.is_ipv6() => a.to_string(),
                _ => {
                    return Err(From::from(format!(
                        "Unable to resolve IP for host : {}",
                        domain
                    )))
                }
            };
        }

        //Connect to plaintext loopback
        debug!("Connecting to loopback");
        let loopback_sock = match TcpStream::connect(ctx.loopback_addr.parse()?) {
            Ok(s) => s,
            Err(e) => return Err(From::from(format!("Failed to connect to loopback : {}", e))),
        };
        let loopback_peer = Peer {
            plain_sock: Some(loopback_sock),
            mid_handshake_sock: None,
            tls_sock: None,
            is_loopback: true,
            loopback_id: None,
            forward_domain: None,
            // This peer forwards data for cli_id
            forward_id: Some(cli_id.0),
            forward_buf: Vec::new(),
        };
        let loopback_id = ctx.add_peer(loopback_peer, registry)?;
        let peer = ctx.connections.get_mut(cli_id).unwrap();
        peer.loopback_id = Some(loopback_id);

        // Connect to remote peer
        let peer_sock =
            match TcpStream::connect(format!("{}:{}", address, ctx.remote_port).parse()?) {
                Ok(s) => s,
                Err(e) => return Err(From::from(format!("Failed to connect to peer : {}", e))),
            };
        let remote_peer = Peer {
            plain_sock: Some(peer_sock),
            mid_handshake_sock: None,
            tls_sock: None,
            is_loopback: false,
            forward_domain: Some(domain.to_owned()),
            loopback_id: Some(loopback_id - 1),
            forward_id: Some(cli_id.0),
            forward_buf: Vec::new(),
        };
        let peer_id = ctx.add_peer(remote_peer, registry)?;
        info!(
            "[{}] Forwarding traffic to [{}] {} ({}:{})",
            cli_id.0, peer_id, domain, address, ctx.remote_port
        );

        // Link current peer to remote peer
        let peer = ctx.connections.get_mut(cli_id).unwrap();
        peer.forward_id = Some(peer_id);
    }

    let peer = ctx.connections.get_mut(cli_id).unwrap();
    let loopback_id = peer.loopback_id;
    let forward_id = peer.forward_id;

    // Dump the request tos stdout
    print_ascii(&forward_data, None);

    //Forward to loopback
    if let Some(loopback_id) = loopback_id {
        if let Some(peer) = ctx.connections.get_mut(&Token(loopback_id)) {
            debug!("Forwarding to loopback {}", loopback_id);
            peer.forward_buf.extend(&forward_data);
            let waker = Waker::new(registry, Token(loopback_id))?;
            waker.wake()?;
        }
    }

    //Forward to remote peer
    if let Some(forward_id) = forward_id {
        if let Some(peer) = ctx.connections.get_mut(&Token(forward_id)) {
            debug!("Forwarding to peer {}", forward_id);
            peer.forward_buf.extend(&forward_data);
            let waker = Waker::new(registry, Token(forward_id))?;
            waker.wake()?;
        }
    }

    Ok(())
}

fn handle_loopback(cli: &mut Peer, event: &Event) -> Result<()> {
    let sock = cli.plain_sock.as_mut().unwrap();
    // Simply flush the recv buffer
    if event.is_readable() {
        // We can (maybe) read from the connection.
        loop {
            let mut buf = vec![];
            match sock.read_to_end(&mut buf) {
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

    if event.is_writable() && !cli.forward_buf.is_empty() {
        match sock.write_all(&cli.forward_buf) {
            Ok(_) => cli.forward_buf.clear(),
            Err(ref err) if would_block(err) => {}
            Err(ref err) if interrupted(err) => {}
            Err(e) => {
                return Err(From::from(format!("Failed to write to socket : {}", e)));
            }
        };
    }

    Ok(())
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

fn print_ascii(bytes: &[u8], max_len: Option<usize>) {
    let mut res = String::with_capacity(bytes.len());
    for b in bytes {
        let ch = *b as char;

        if ch.is_ascii() {
            res.push(ch);
        } else {
            res.push('?');
        }
    }

    let max_len = match max_len {
        Some(v) => v,
        None => 256,
    };

    if res.len() > max_len {
        let mut tmp = String::with_capacity(256);
        tmp.push_str(&res[0..max_len / 2]);
        tmp.push_str("<...>");
        tmp.push_str(&res[res.len() - (max_len / 2)..]);
        res = tmp;
    }
    println!("\n\t{}", res);
}

fn cleanup_peer(peer_id: usize, registry: &Registry, ctx: &mut Ctx) {
    let mut peer = match ctx.connections.remove(&Token(peer_id)) {
        None => return,
        Some(p) => p,
    };

    debug!(
        "Closing peer {} {}",
        peer_id,
        if peer.is_loopback { "(Loopback)" } else { "" }
    );
    // Close the connection cleanly
    let sock = if let Some(ref mut sock) = peer.plain_sock {
        let _ = registry.deregister(sock);
        Some(sock)
    } else if let Some(ref mut sock) = peer.mid_handshake_sock {
        let plain_sock = sock.get_mut();
        let _ = registry.deregister(plain_sock);
        Some(plain_sock)
    } else if let Some(ref mut sock) = peer.tls_sock {
        let plain_sock = sock.get_mut();
        let _ = registry.deregister(plain_sock);
        Some(plain_sock)
    } else {
        None
    };
    // Close TCP socket
    if let Some(s) = sock {
        let _ = s.shutdown(std::net::Shutdown::Both);
    }

    // Shutdown loopback streams if present
    if let Some(loopback_id) = peer.loopback_id {
        cleanup_peer(loopback_id, registry, ctx);
    }
    // If we were forwarding to a remote peer, shutdown that peer too
    if let Some(forward_id) = peer.forward_id {
        cleanup_peer(forward_id, registry, ctx);
    }
}
