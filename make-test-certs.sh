#!/bin/bash

#
# create some CA/certs/keys for testing
#

# Certificate generation script for example.com hierarchy
# Creates a root CA, sub CA, and test certificates

set -e

echo "output will be going into the certz directory..."

mkdir -p certz
cd certz

echo "Generating CA hierarchy and test certificates..."

# Clean up any existing files
rm -f *.pem *.key *.csr *.srl tinman-ed25519*

# Create serial number files
echo "01" > ca-serial.txt
echo "01" > sub-ca-serial.txt

#=============================================================================
# ROOT CA (example.com)
#=============================================================================

echo "Creating Root CA private key..."
openssl genrsa -out root-ca.key 2048

echo "Creating Root CA certificate..."
openssl req -new -x509 -key root-ca.key -out root-ca.pem -days 365 -subj "/C=OZ/ST=OZ/L=Emerald City/O=The Wiz/CN=example.com"

#=============================================================================
# SUB CA (ca.oz.example.com)
#=============================================================================

echo "Creating Sub CA private key..."
openssl genrsa -out sub-ca.key 2048

echo "Creating Sub CA certificate signing request..."
openssl req -new -key sub-ca.key -out sub-ca.csr -subj "/C=OZ/ST=Winkie Country/O=Wicked Witch of the West/OU=Flying Monkees/CN=ca.oz.example.com"

echo "Creating Sub CA certificate..."
openssl x509 -req -in sub-ca.csr -CA root-ca.pem -CAkey root-ca.key -CAserial ca-serial.txt -out sub-ca.pem -days 365 -extensions v3_ca -extfile <(cat <<EOF
[v3_ca]
basicConstraints = CA:TRUE
keyUsage = keyCertSign, cRLSign
EOF
)

#=============================================================================
# ROOT CA ISSUED CERTIFICATE (test.example.com)
#=============================================================================

echo "Creating test.example.com private key..."
openssl genrsa -out test.example.com.key 2048

echo "Creating test.example.com certificate signing request..."
openssl req -new -key test.example.com.key -out test.example.com.csr -subj "/C=OZ/ST=Winkie Country/O=Nellary/CN=test.example.com"

echo "Creating test.example.com certificate (issued by Root CA)..."
openssl x509 -req -in test.example.com.csr -CA root-ca.pem -CAkey root-ca.key -CAserial ca-serial.txt -out test.example.com.pem -days 365

#=============================================================================
# SUB CA ISSUED CERTIFICATES
#=============================================================================

# Certificate 1: Key Encipherment (one.oz.example.com)
echo "Creating one.oz.example.com private key..."
openssl genrsa -out one.oz.example.com.key 2048

echo "Creating one.oz.example.com certificate signing request..."
openssl req -new -key one.oz.example.com.key -out one.oz.example.com.csr -subj "/C=OZ/ST=Winkie Country/OU=Frogman/CN=one.oz.example.com"

echo "Creating one.oz.example.com certificate (Key Encipherment)..."
openssl x509 -req -in one.oz.example.com.csr -CA sub-ca.pem -CAkey sub-ca.key -CAserial sub-ca-serial.txt -out one.oz.example.com.pem -days 365 -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = critical, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

# Certificate 2: TLS Web Server Authentication (www.oz.example.com)
echo "Creating www.oz.example.com private key..."
openssl genrsa -out www.oz.example.com.key 2048

echo "Creating www.oz.example.com certificate signing request..."
openssl req -new -key www.oz.example.com.key -out www.oz.example.com.csr -subj "/C=OZ/ST=Winkie Country/OU=Engineering/CN=www.oz.example.com"

echo "Creating www.oz.example.com certificate (TLS Web Server Authentication)..."
openssl x509 -req -in www.oz.example.com.csr -CA sub-ca.pem -CAkey sub-ca.key -CAserial sub-ca-serial.txt -out www.oz.example.com.pem -days 365 -extensions v3_req -extfile <(cat <<EOF
[v3_req]
extendedKeyUsage = serverAuth
EOF
)

# Certificate 3: TLS Web Client Authentication (client.oz.example.com)
echo "Creating client.oz.example.com private key..."
openssl genrsa -out client.oz.example.com.key 2048

echo "Creating client.oz.example.com certificate signing request..."
openssl req -new -key client.oz.example.com.key -out client.oz.example.com.csr -subj "/C=OZ/ST=Winkie Country/OU=Herku/CN=client.oz.example.com"

echo "Creating client.oz.example.com certificate (TLS Web Client Authentication)..."
openssl x509 -req -in client.oz.example.com.csr -CA sub-ca.pem -CAkey sub-ca.key -CAserial sub-ca-serial.txt -out client.oz.example.com.pem -days 365 -extensions v3_req -extfile <(cat <<EOF
[v3_req]
extendedKeyUsage = clientAuth
EOF
)


#=============================================================================
# some one-off keys n things
#=============================================================================

echo "Creating rinktinktink.example.com private key..."
openssl genrsa -out rinktinktink.example.com.key 2048

echo "Creating toto.example.com private key..."
openssl genrsa -out toto.example.com.key 2048

echo "Creating tinman.example.com SSH key pair"
ssh-keygen -t ed25519 -C "tinman@example.com" -f tinman-ed25519 -N ""

#=============================================================================
# CLEANUP AND SUMMARY
#=============================================================================

echo "Cleaning up temporary files..."
rm -f *.csr *.srl *-serial.txt

echo ""
echo "Certificate generation complete!"
echo ""
echo "Files created (in certz subdirectory):"
echo "======================================"
echo "Root CA:"
echo "  root-ca.key - Root CA private key"
echo "  root-ca.pem - Root CA certificate"
echo ""
echo "Sub CA:"
echo "  sub-ca.key - Sub CA private key"
echo "  sub-ca.pem - Sub CA certificate (issued by Root CA)"
echo ""
echo "End-entity certificates:"
echo "  test.example.com.key/.pem - General test cert (issued by Root CA)"
echo "  one.oz.example.com.key/.pem - Key Encipherment cert (issued by Sub CA)"
echo "  www.oz.example.com.key/.pem - TLS Server Auth cert (issued by Sub CA)"
echo "  client.oz.example.com.key/.pem - TLS Client Auth cert (issued by Sub CA)"
echo ""
echo "SSH key pair:"
echo "  tinman-ed25519     - private key"
echo "  tinman-ed25519.pub - public key"
echo ""
echo "X.509 private keys with no corresponding cert"
echo ""
echo "  toto.example.com.key"
echo "  rinktinktink.example.com.key"
echo ""
echo "To verify the certificate chain, you can use:"
echo "  openssl verify -CAfile root-ca.pem sub-ca.pem"
echo "  openssl verify -CAfile root-ca.pem -untrusted sub-ca.pem one.oz.example.com.pem"
echo ""

