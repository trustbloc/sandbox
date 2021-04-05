#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating test certs ..."
export RANDFILE=/tmp/rnd


if [ "${DOMAIN}x" == "x" -o "${CERTS_OUTPUT_DIR}x" == "x" ]; then
    echo "DOMAIN/CERTS_OUTPUT_DIR env not set"
    exit 1
fi

cd /opt/workspace

mkdir -p ${CERTS_OUTPUT_DIR}

trustblocSSLConf=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.${DOMAIN}" >> "$trustblocSSLConf"

CERT_CA="${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt"
if [ ! -f "$CERT_CA" ]; then
    echo "... Generating CA cert ..."
    openssl ecparam -name prime256v1 -genkey -noout \
      -out ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key
    openssl req -new -x509 -key ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key \
      -subj "/C=CA/ST=ON/O=TrustBloc/OU=TrustBloc Dev CA" \
      -out ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt -days 1095
else
    echo "Skipping CA generation - already exists"
fi

echo "... Generating TrustBloc domain cert:  ${DOMAIN} ..."

openssl ecparam -name prime256v1 -genkey -noout \
  -out ${CERTS_OUTPUT_DIR}/${DOMAIN}.key

openssl req -new -key ${CERTS_OUTPUT_DIR}/${DOMAIN}.key \
  -subj "/C=CA/ST=ON/O=TrustBloc/OU=trustbloc/CN=${DOMAIN}" \
  -out ${CERTS_OUTPUT_DIR}/${DOMAIN}.csr

openssl x509 -req -in ${CERTS_OUTPUT_DIR}/${DOMAIN}.csr \
  -CA ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt \
  -CAkey ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.key \
  -CAcreateserial -CAserial ${CERTS_OUTPUT_DIR}/${DOMAIN}.srl -extfile "$trustblocSSLConf" \
  -out ${CERTS_OUTPUT_DIR}/${DOMAIN}.crt -days 365

# RFC 4346 Append CA to CERT
cat ${CERTS_OUTPUT_DIR}/trustbloc-dev-ca.crt >> ${CERTS_OUTPUT_DIR}/${DOMAIN}.crt

echo "... Done generating test certs"
