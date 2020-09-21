# Generate custom CA key
openssl genrsa -out rootCA.key 2048
# Create self signed root cert
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt

# --------- FOR EACH SITE ---------

# Generate key
openssl genrsa -out domain.com.key 2048
# Generate csr
openssl req -new -key domain.com.key -out domain.com.csr -config cert.cnf

# Generate cert
openssl x509 -req -in domain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out domain.com.crt -days 500 -sha256 -extfile cert.cnf -extensions req_ext
# Generate pfx bundle
openssl pkcs12 -export -out domain.com.pfx -inkey domain.com.key -in domain.com.crt

### cert.cnf
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext

[ req_distinguished_name ]
countryName                 = Country Name (2 letter code)
countryName_default         = US
stateOrProvinceName         = State or Province Name (full name)
stateOrProvinceName_default = NY
localityName                = Locality Name (eg, city)
localityName_default        = New-York
organizationName            = Organization Name (eg, company)
organizationName_default    = Company LTD
commonName                  = Common Name (e.g. server FQDN or YOUR name)
commonName_max              = 64
commonName_default          = domain.com

[ req_ext ]
subjectAltName = @alt_names

[alt_names]
DNS.1   = www.domain.com
DNS.2   = test.domain.com