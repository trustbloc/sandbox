#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

registerRPTenant() {
    n=0
    maxAttempts=30

    until [ $n -ge $maxAttempts ]
    do
        response=$(curl -o - -s -w "RESPONSE_CODE=%{response_code}" \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{"label": "rp.trustbloc.local", "callback": "https://rp.trustbloc.local/oauth2/callback"}' \
        http://rp.adapter.rest.example.com:10161/relyingparties)

        code=${response//*RESPONSE_CODE=/}

        if [[ $code -eq 201 ]]
        then
            echo "${response}"
            break
        fi

        n=$((n+1))
        if [ $n -eq $maxAttempts ]
        then
            echo "Failed to register RP Tenant: $response"
            break
        fi
        sleep 5
    done
}

echo "Waiting for the RP Adapter to be ready..."
# TODO implement a smart healthcheck on RP Adapter: https://github.com/trustbloc/edge-adapter/issues/134
sleep 30
echo "Registering RP Adapter tenant..."
result=$(registerRPTenant)
registration=${result//RESPONSE_CODE*/}
code=${result//*RESPONSE_CODE=/}
if [ $code -ne 201 ]
then
    echo "Failed to register RP Tenant!"
    echo "   HTTP STATUS CODE: $code"
    echo "   HTTP RESPONSE: $registration"
    exit 1
fi

clientID=$(echo $registration | jq .clientID)
clientSecret=$(echo $registration | jq .clientSecret)
publicDID=$(echo $registration | jq .publicDID)

echo "RP Tenant ClientID=$clientID PublicDID=$publicDID."
echo ""

echo "Starting rp.example.com..."
rp-rest start --oidc-opurl https://rp-adapter-hydra.trustbloc.local:6666/ --oidc-clientid $clientID --oidc-clientsecret $clientSecret
