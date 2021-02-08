#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Running $0"


dockerComposeFiles="-f docker-compose-sidetree-fabric.yml -f docker-compose-sidetree-mock-discovery.yml -f docker-compose-sidetree-mock.yml -f docker-compose-dbs.yml -f docker-compose-cms.yml -f docker-compose-edv.yml -f docker-compose-resolver.yml -f docker-compose-registrar.yml -f docker-compose-did-method.yml -f docker-compose-vcs.yml -f docker-compose-kms.yml -f docker-compose-auth.yml -f docker-compose-wallet.yml -f docker-compose-adapter.yml -f docker-compose-demo-applications.yml -f docker-compose-comparator.yml  $sidetreeCompseFile"
(cd test/bdd/fixtures/demo && docker-compose $dockerComposeFiles down)

echo ""
echo "Sandbox stopped!"
