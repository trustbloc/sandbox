#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating edge-sandbox Test PKI"

cd /opt/workspace/edge-sandbox
mkdir -p test/bdd/fixtures/keys/tls
localhostSSLConf=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = testnet.trustbloc.local
DNS.3 = stakeholder.one
DNS.4 = sidetree-mock" >> "$localhostSSLConf"

trustblocSSLConf=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.trustbloc.local" >> "$trustblocSSLConf"

CERT_CA="test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt"
if [ ! -f "$CERT_CA" ]; then
    echo "Generating CA cert"
    openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key
    openssl req -new -x509 -key test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key -subj "/C=CA/ST=ON/O=TrustBloc/OU=TrustBloc Dev CA" -out test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt -days 1095
else
    echo "Skipping CA generation - already exists"
fi

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/localhost.key
openssl req -new -key test/bdd/fixtures/keys/tls/localhost.key -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc-edge-sandbox/CN=localhost" -out test/bdd/fixtures/keys/tls/localhost.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/localhost.csr -CA test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt -CAkey test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key -CAcreateserial -extfile "$localhostSSLConf" -out test/bdd/fixtures/keys/tls/localhost.crt -days 365

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/trustbloc.local.key
openssl req -new -key test/bdd/fixtures/keys/tls/trustbloc.local.key -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc-edge-sandbox/CN=trustbloc.local" -out test/bdd/fixtures/keys/tls/trustbloc.local.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/trustbloc.local.csr -CA test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt -CAkey test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key -CAcreateserial -extfile "$trustblocSSLConf" -out test/bdd/fixtures/keys/tls/trustbloc.local.crt -days 365


# generate key pair
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/key.pem
openssl ec -in test/bdd/fixtures/keys/key.pem -pubout -out test/bdd/fixtures/keys/public.pem

echo "done generating edge-sandbox PKI"
