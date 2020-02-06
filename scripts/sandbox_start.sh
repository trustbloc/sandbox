#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

cd test/bdd/fixtures/demo
dockerComposeFiles='-f docker-compose-third-party.yml -f docker-compose-router.yml -f docker-compose-sidetree-mock.yml -f docker-compose-edge-components.yml -f docker-compose-demo-applications.yml'
(source .env && docker-compose $dockerComposeFiles down && docker-compose $dockerComposeFiles up --force-recreate)


