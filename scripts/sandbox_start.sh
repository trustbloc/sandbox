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
exit
}


sidetreeCompseFile='-f docker-compose-sidetree-mock.yml'
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    setupFabric &
    sidetreeCompseFile='-f docker-compose-sidetree-fabric.yml'
else
    # create sidetree-mock discovery server data folders
    mkdir -p test/bdd/fixtures/discovery-config/sidetree-mock/config/did-trustbloc
    mkdir -p test/bdd/fixtures/discovery-config/sidetree-mock/config/stakeholder-one.trustbloc.local
fi
dockerComposeFiles="-f docker-compose-third-party.yml -f docker-compose-didcomm.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml -f docker-compose-universal-resolver.yml -f docker-compose-universal-registrar.yml $sidetreeCompseFile"
(cd test/bdd/fixtures/demo ; (docker-compose $dockerComposeFiles down && docker-compose $dockerComposeFiles up --force-recreate))

if [ "$START_SIDETREE_FABRIC" != true ] ; then
    # generate sidetree-mock discovery configs
    (cd test/bdd; sleep 60; . ./generate_did_method_config_mock.sh; echo "FINISHED GENERATING DID-METHOD CONFIG")
fi

