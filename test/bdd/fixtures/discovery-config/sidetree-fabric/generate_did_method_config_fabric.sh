#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

rm -rf ./fixtures/discovery-config/sidetree-fabric/config

../../.build/did-method-cli/cli create-config --sidetree-url https://peer0-org1.trustbloc.local/sidetree/0.0.1 \
--tls-cacerts ./fixtures/keys/tls/trustbloc-dev-ca.crt --sidetree-write-token rw_token \
--config-file ./fixtures/discovery-config/sidetree-fabric/config-data-generated/testnet.trustbloc.local.json --output-directory ./fixtures/discovery-config/sidetree-fabric/config
