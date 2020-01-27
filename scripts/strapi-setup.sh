#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

# This is assuming strapi is running on default 1337 port
cd build/bin
./strapi-demo create-demo-data --host-url http://localhost:1337

sed -e "s/{TOKEN}/$(sed 's:/:\\/:g' ./strapi.txt)/" ../../test/bdd/fixtures/oathkeeper/rules/resource-server-template.json > ../../test/bdd/fixtures/oathkeeper/rules/resource-server.json

