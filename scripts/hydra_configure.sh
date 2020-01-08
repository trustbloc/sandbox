#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Running $0"

cd test/bdd/fixtures/hydra

#Figure out how to cofigure client without docker-compose
docker-compose exec hydra \
    hydra clients create \
    --endpoint http://127.0.0.1:4445 \
    --id auth-code-client \
    --secret secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope studentcard \
    --callbacks http://127.0.0.1:5555/callback
