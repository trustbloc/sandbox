#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

../../.build/did-method-cli/cli create-config --sidetree-url https://peer0-org1.trustbloc.local/sidetree/0.0.1 \
--tls-cacerts ./fixtures/keys/tls/trustbloc-dev-ca.crt --sidetree-write-token rw_token \
--config-file ./fixtures/discovery-config/sidetree-mock/config-data/config.json --output-directory ./fixtures/discovery-config/sidetree-mock/config

mv ./fixtures/discovery-config/sidetree-mock/config/stakeholder-one.trustbloc.local/did-configuration.json ./fixtures/discovery-config/sidetree-mock/config
