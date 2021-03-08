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
    --scope StudentCard,TravelCard,PermanentResidentCard,VaccinationCertificate,CertifiedMillTestReport,CrudeProductCredential,UniversityDegreeCredential,CreditCardStatement,mDL,CreditScore \
    --skip-tls-verify \
    --callbacks https://issuer.trustbloc.local/callback
echo "Finish Creating client"

echo "Creating hub-auth client"
# will use --skip-tls-verify because hydra doesn't trust self-signed certificate
# remove it when using real certificate
hydra clients create \
    --endpoint https://hydra.trustbloc.local:4445 \
    --id hub-auth \
    --secret hub-auth-secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,profile,email \
    --skip-tls-verify \
    --callbacks https://auth-rest.trustbloc.local/oauth2/callback
echo "Finished creating hub-auth client"
