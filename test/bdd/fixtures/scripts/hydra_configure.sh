#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Create client"
# will use --skip-tls-verify because hydra doesn't trust self-signed certificate
# remove it when using real certificate
hydra clients create \
    --endpoint https://hydra.trustbloc.local:4445 \
    --id auth-code-client \
    --secret secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope StudentCard,TravelCard,PRCard,CertifiedMillTestReport,CrudeProductCredential \
    --skip-tls-verify \
    --callbacks https://issuer.trustbloc.local/callback
echo "Finish Creating client"
