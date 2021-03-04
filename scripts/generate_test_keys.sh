#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating sandbox Test PKI"

cd /opt/workspace/sandbox
mkdir -p test/bdd/fixtures/keys/tls
mkdir -p test/bdd/fixtures/keys/recover
mkdir -p test/bdd/fixtures/keys/update
mkdir -p test/bdd/fixtures/keys/update2
mkdir -p test/bdd/fixtures/keys/recover-org1
mkdir -p test/bdd/fixtures/keys/update-org1
mkdir -p test/bdd/fixtures/keys/update2-org1
mkdir -p test/bdd/fixtures/keys/recover-org2
mkdir -p test/bdd/fixtures/keys/update-org2
mkdir -p test/bdd/fixtures/keys/update2-org2
mkdir -p test/bdd/fixtures/keys/recover-org3
mkdir -p test/bdd/fixtures/keys/update-org3
mkdir -p test/bdd/fixtures/keys/update2-org3
mkdir -p test/bdd/fixtures/keys/session_cookies

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
openssl req -new -key test/bdd/fixtures/keys/tls/localhost.key -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc-sandbox/CN=localhost" -out test/bdd/fixtures/keys/tls/localhost.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/localhost.csr -CA test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt -CAkey test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key -CAcreateserial -extfile "$localhostSSLConf" -out test/bdd/fixtures/keys/tls/localhost.crt -days 365

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/trustbloc.local.key
openssl req -new -key test/bdd/fixtures/keys/tls/trustbloc.local.key -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc-sandbox/CN=trustbloc.local" -out test/bdd/fixtures/keys/tls/trustbloc.local.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/trustbloc.local.csr -CA test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt -CAkey test/bdd/fixtures/keys/tls/trustbloc-dev-ca.key -CAcreateserial -extfile "$trustblocSSLConf" -out test/bdd/fixtures/keys/tls/trustbloc.local.crt -days 365

# generate key pair for recover/updates
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover/key.pem
openssl ec -in test/bdd/fixtures/keys/recover/key.pem -pubout -out test/bdd/fixtures/keys/recover/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update/key.pem
openssl ec -in test/bdd/fixtures/keys/update/key.pem -pubout -out test/bdd/fixtures/keys/update/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update2/key.pem
openssl ec -in test/bdd/fixtures/keys/update2/key.pem -pubout -out test/bdd/fixtures/keys/update2/public.pem


# generate key pairs for org-specific wellknown
# org 1
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover-org1/key.pem
openssl ec -in test/bdd/fixtures/keys/recover-org1/key.pem -pubout -out test/bdd/fixtures/keys/recover-org1/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update-org1/key.pem
openssl ec -in test/bdd/fixtures/keys/update-org1/key.pem -pubout -out test/bdd/fixtures/keys/update-org1/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update2-org1/key.pem
openssl ec -in test/bdd/fixtures/keys/update2-org1/key.pem -pubout -out test/bdd/fixtures/keys/update2-org1/public.pem
# org 2
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover-org2/key.pem
openssl ec -in test/bdd/fixtures/keys/recover-org2/key.pem -pubout -out test/bdd/fixtures/keys/recover-org2/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update-org2/key.pem
openssl ec -in test/bdd/fixtures/keys/update-org2/key.pem -pubout -out test/bdd/fixtures/keys/update-org2/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update2-org2/key.pem
openssl ec -in test/bdd/fixtures/keys/update2-org2/key.pem -pubout -out test/bdd/fixtures/keys/update2-org2/public.pem
# org 3
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover-org3/key.pem
openssl ec -in test/bdd/fixtures/keys/recover-org3/key.pem -pubout -out test/bdd/fixtures/keys/recover-org3/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update-org3/key.pem
openssl ec -in test/bdd/fixtures/keys/update-org3/key.pem -pubout -out test/bdd/fixtures/keys/update-org3/public.pem
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update2-org3/key.pem
openssl ec -in test/bdd/fixtures/keys/update2-org3/key.pem -pubout -out test/bdd/fixtures/keys/update2-org3/public.pem

# create session cookie keys
openssl rand -out test/bdd/fixtures/keys/session_cookies/auth.key 32
openssl rand -out test/bdd/fixtures/keys/session_cookies/enc.key 32

# create secrete lock key
openssl rand 32 | base64 | sed 's/+/-/g; s/\//_/g' > test/bdd/fixtures/keys/tls/secret-lock.key

echo "done generating sandbox PKI"
