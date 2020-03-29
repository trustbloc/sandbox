#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Create client"
hydra clients create \
    --endpoint http://hydra:4445 \
    --id auth-code-client \
    --secret secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope StudentCard,TravelCard \
    --callbacks https://issuer.trustbloc.local/callback
echo "Finish Creating client"
