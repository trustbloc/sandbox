#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating test keys ..."
export RANDFILE=/tmp/rnd

if [ "${KEYS_OUTPUT_DIR}x" == "x" ]; then
    echo "KEYS_OUTPUT_DIR env not set"
    exit 1
fi

cd /opt/workspace

mkdir -p ${KEYS_OUTPUT_DIR}

# create session cookie keys
openssl rand -out ${KEYS_OUTPUT_DIR}/auth.key 32
openssl rand -out ${KEYS_OUTPUT_DIR}/enc.key 32

echo "... Done generating test keys"
