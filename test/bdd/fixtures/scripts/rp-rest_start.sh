#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

rpAdapterURL=https://rp.adapter.rest.example.com:10161/relyingparties
callbackURL=https://rp.trustbloc.local:5557/oauth2/callback

registerRPTenant() {
    n=0

    # TODO implement a smart healthcheck on RP Adapter: https://github.com/trustbloc/edge-adapter/issues/134
    maxAttempts=60

    until [ $n -ge $maxAttempts ]
    do
        response=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{"label": "rp.trustbloc.local", "callback": "'$callbackURL'"}' \
        $rpAdapterURL)

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

echo "Registering RP Adapter tenant at "$rpAdapterURL
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

clientID=$(echo $registration | jq -r .clientID)
clientSecret=$(echo $registration | jq -r .clientSecret)
publicDID=$(echo $registration | jq -r .publicDID)

echo "RP Tenant ClientID=$clientID Callback=$callbackURL PublicDID=$publicDID"
echo ""

echo "Starting rp.example.com..."
rp-rest start --oidc-clientid $clientID --oidc-clientsecret $clientSecret
