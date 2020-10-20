#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

hash=$(.build/did-method-cli/cli config-hash --config-file test/bdd/fixtures/discovery-config/sidetree-mock/config-data/testnet.trustbloc.local.json)

echo "sidetree-mock config hash: $hash"

hash=$(.build/did-method-cli/cli config-hash --config-file test/bdd/fixtures/discovery-config/sidetree-fabric/config-data/testnet.trustbloc.local.json)

echo "sidetree-fabric config hash: $hash"
