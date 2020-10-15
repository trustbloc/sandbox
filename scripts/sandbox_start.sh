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
}

generateDIDMethodConfigMock(){
n=0
maxAttempts=10
while true
do
if .build/did-method-cli/cli create-config --sidetree-url https://sidetree-mock.trustbloc.local/sidetree/0.0.1 \
--tls-cacerts ./test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt --sidetree-write-token rw_token \
--config-file ./test/bdd/fixtures/discovery-config/sidetree-mock/config-data/testnet.trustbloc.local.json --output-directory ./test/bdd/fixtures/discovery-config/sidetree-mock/temp > /dev/null 2>&1; then
  echo "create did-method config successfully"
  break
fi

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create did-method config"
     exit 1
   fi
   sleep 5
done

rm -rf ./test/bdd/fixtures/discovery-config/sidetree-mock/config/did-trustbloc
mv ./test/bdd/fixtures/discovery-config/sidetree-mock/temp/did-trustbloc ./test/bdd/fixtures/discovery-config/sidetree-mock/config
mv ./test/bdd/fixtures/discovery-config/sidetree-mock/temp/stakeholder-one.trustbloc.local/did-configuration.json ./test/bdd/fixtures/discovery-config/sidetree-mock/config

rm -rf ./test/bdd/fixtures/discovery-config/sidetree-mock/temp
}

# select compose files
sidetreeCompseFile='-f docker-compose-sidetree-mock.yml'
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    sidetreeCompseFile='-f docker-compose-sidetree-fabric.yml'
fi
dockerComposeFiles="-f docker-compose-third-party.yml -f docker-compose-didcomm.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml -f docker-compose-universal-resolver.yml -f docker-compose-universal-registrar.yml $sidetreeCompseFile"
(cd test/bdd/fixtures/demo ;docker-compose $dockerComposeFiles pull --ignore-pull-failures || true)

# setup
if [ "$START_SIDETREE_FABRIC" = true ] ; then
    setupFabric &
else
  generateDIDMethodConfigMock &
fi

# start demo
(cd test/bdd/fixtures/demo ; (docker-compose $dockerComposeFiles down && docker-compose $dockerComposeFiles up --force-recreate))
