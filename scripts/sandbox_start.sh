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
curl -d '{"name":"vc-issuer-1", "uri":"http://vc-issuer-1.com", "signatureType":"Ed25519Signature2018"}' -H "Content-Type: application/json" -X POST http://localhost:8070/profile
curl -d '{"name":"vc-issuer-2", "uri":"http://vc-issuer-2.com", "signatureType":"Ed25519Signature2018", "did":"did:v1:test:nym:z6MkhLbRigh9utJNCaiEAdkqktz4r7yVBFDeaeqCeT7pRFnF","didPrivateKey":"5dF8yAW7hjLkJsfMXKqTPdDZUT56dX7Jq7TdXEtUEHHt2YUFAE34nQwyPCEp5XdWCKPSxs69xXqozsNh6MoJTmz5"}' -H "Content-Type: application/json" -X POST http://localhost:8070/profile
}


sidetreeCompseFile='-f docker-compose-sidetree-mock.yml'
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    setupFabric &
    export SIDETREE_HOST_URL="http://peer0.org1.example.com:48326/document"
    sidetreeCompseFile='-f docker-compose-sidetree-fabric.yml'
fi
dockerComposeFiles="-f docker-compose-third-party.yml -f docker-compose-router.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml -f docker-compose-universal-resolver.yml $sidetreeCompseFile"
(cd test/bdd/fixtures/demo ; (docker-compose $dockerComposeFiles down && docker-compose $dockerComposeFiles up --force-recreate))
