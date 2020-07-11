#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Running $0"

sidetreeCompseFile='-f docker-compose-sidetree-mock.yml'
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    sidetreeCompseFile='-f docker-compose-sidetree-fabric.yml'
fi

dockerComposeFiles="-f docker-compose-third-party.yml -f docker-compose-didcomm.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml -f docker-compose-universal-resolver.yml -f docker-compose-universal-registrar.yml $sidetreeCompseFile"
(cd test/bdd/fixtures/demo && docker-compose $dockerComposeFiles down)

echo ""
echo "Sandbox stopped!"
