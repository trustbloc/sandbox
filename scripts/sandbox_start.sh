#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"



setupFabric() {
# wait until peer is up
# TODO we need health check for peer
sleep 20
cd test/bdd && go test
curl -d '{"name":"demo", "did":"did:demo:abc", "uri":"http://demo.com", "signatureType":"Ed25519Signature2018", "creator":"did:demo:abc#key1" }' -H "Content-Type: application/json" -X POST http://localhost:8070/profile
}


sidetreeCompseFile='-f docker-compose-sidetree-mock.yml'
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    setupFabric &
    export SIDETREE_HOST_URL="http://peer0.org1.example.com:48326/document"
    sidetreeCompseFile='-f docker-compose-sidetree-fabric.yml'
fi
dockerComposeFiles="-f docker-compose-third-party.yml -f docker-compose-router.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml $sidetreeCompseFile"
(cd test/bdd/fixtures/demo ; (docker-compose $dockerComposeFiles down && docker-compose $dockerComposeFiles up --force-recreate))
