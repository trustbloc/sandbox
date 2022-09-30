#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Adding curl and jq"
apk --no-cache add curl jq

# If necessary, convert the reported architecture name to the (equivalent) names that are used in the kubectl binary
# filenames.
ARCH=$( uname -m)
case $ARCH in
   x86_64)
     ARCH="amd64"
     ;;
   aarch64)
     ARCH="arm64"
     ;;
esac

echo
echo "fetching kubectl"
curl -qL https://storage.googleapis.com/kubernetes-release/release/v1.20.0/bin/linux/$ARCH/kubectl -o /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl

rpAdapterURL=https://adapter-rp.||DOMAIN||/relyingparties
callbackURL=https://demo-rp.||DOMAIN||/oauth2/callback

# begin - register non-waci tenant at adapter-rp
registerRPTenant() {
    n=0

    # TODO implement a smart healthcheck on RP Adapter: https://github.com/trustbloc/edge-adapter/issues/134
    maxAttempts=60

    until [ $n -ge $maxAttempts ]
    do
        response=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{"label": "demo-rp.||DOMAIN||", "callback": "'$callbackURL'", "scopes": ["credit_card_stmt:remote","driver_license:local","credit_score:remote","driver_license_evidence:remote"], "isDIDCommV1" : true, "requiresBlindedRoute": true}' \
        --insecure $rpAdapterURL)

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
scopes=$(echo $registration | jq -r .scopes)
requiresBlindedRoute=$(echo $registration | jq -r .requiresBlindedRoute)

echo "RP Tenant ClientID=$clientID Callback=$callbackURL Scopes=$scopes PublicDID=$publicDID requiresBlindedRoute=$requiresBlindedRoute"
echo ""
# end - register non-waci tenant at adapter-rp

# begin - register waci tenant at adapter-rp
registerWACIRPTenant() {
    n=0

    # TODO implement a smart healthcheck on RP Adapter: https://github.com/trustbloc/edge-adapter/issues/134
    maxAttempts=60

    until [ $n -ge $maxAttempts ]
    do
        response=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{"label": "demo-rp.||DOMAIN||", "callback": "'$callbackURL'", "scopes": ["prc:local","driver_license:local"], "supportsWACI": true, "linkedWalletURL":"https://wallet.||DOMAIN||/waci"}' \
        --insecure $rpAdapterURL)

        code=${response//*RESPONSE_CODE=/}

        if [[ $code -eq 201 ]]
        then
            echo "${response}"
            break
        fi

        n=$((n+1))
        if [ $n -eq $maxAttempts ]
        then
            echo "Failed to register WACI RP Tenant: $response"
            break
        fi
        sleep 5
    done
}

echo "Registering WACI RP Adapter tenant at "$rpAdapterURL
result=$(registerWACIRPTenant)
registration=${result//RESPONSE_CODE*/}
code=${result//*RESPONSE_CODE=/}
if [ $code -ne 201 ]
then
    echo "Failed to register RP Tenant!"
    echo "   HTTP STATUS CODE: $code"
    echo "   HTTP RESPONSE: $registration"
    exit 1
fi

waciClientID=$(echo $registration | jq -r .clientID)
waciClientSecret=$(echo $registration | jq -r .clientSecret)
waciPublicDID=$(echo $registration | jq -r .publicDID)
waciScopes=$(echo $registration | jq -r .scopes)
supportsWACI=$(echo $registration | jq -r .supportsWACI)
linkedWalletURL=$(echo $registration | jq -r .linkedWalletURL)


echo "WACI RP Tenant ClientID=$waciClientID Callback=$callbackURL Scopes=$waciScopes PublicDID=$waciPublicDID supportsWACI=$supportsWACI linkedWalletURL=$linkedWalletURL"
echo ""
# end - register waci tenant at adapter-rp

echo
config_map_name=$(kubectl get pods -l component=rp,group=demo -o jsonpath='{.items[-1:].spec.containers[0].envFrom[0].configMapRef.name}' --sort-by=.metadata.creationTimestamp)
config_map_data=$(mktemp)
config_map_env_file=$(mktemp)
config_map=$(mktemp)
kubectl get cm ${config_map_name} -o jsonpath='{.data}' > ${config_map_data}
cm_keys=$(cat ${config_map_data} | jq -r 'keys[]')
for key in $cm_keys
do
  q=".[\"$key\"]"
  v=$(cat ${config_map_data} | jq -r $q)
  echo "$key=$v" | sed -E 's/(^.+)="([^"]*)"/\1=\2/' >> ${config_map_env_file}
done

grep -q '^RP_OIDC_CLIENTID' ${config_map_env_file} &&  sed -i "s/^RP_OIDC_CLIENTID.*/RP_OIDC_CLIENTID=${clientID}/" ${config_map_env_file} || echo "RP_OIDC_CLIENTID=${clientID}" >> ${config_map_env_file}
grep -q '^RP_OIDC_CLIENTSECRET' ${config_map_env_file} &&  sed -i "s/^RP_OIDC_CLIENTSECRET.*/RP_OIDC_CLIENTSECRET=${clientSecret}/" ${config_map_env_file} || echo "RP_OIDC_CLIENTSECRET=${clientSecret}" >> ${config_map_env_file}

grep -q '^RP_WACI_OIDC_CLIENTID' ${config_map_env_file} &&  sed -i "s/^RP_WACI_OIDC_CLIENTID.*/RP_WACI_OIDC_CLIENTID=${waciClientID}/" ${config_map_env_file} || echo "RP_WACI_OIDC_CLIENTID=${waciClientID}" >> ${config_map_env_file}
grep -q '^RP_WACI_OIDC_CLIENTSECRET' ${config_map_env_file} &&  sed -i "s/^RP_WACI_OIDC_CLIENTSECRET.*/RP_WACI_OIDC_CLIENTSECRET=${waciClientSecret}/" ${config_map_env_file} || echo "RP_WACI_OIDC_CLIENTSECRET=${waciClientSecret}" >> ${config_map_env_file}

echo "mutating configMap ${config_map_name}"
kubectl create cm ${config_map_name} --dry-run=client --from-env-file=${config_map_env_file} -o yaml > ${config_map}
echo
cat ${config_map}
echo
kubectl apply -f ${config_map}
echo "labeling"
kubectl label --overwrite cm ${config_map_name} component=rp group=demo project=trustbloc instance=||DEPLOYMENT_ENV||

echo "recycling rp deployment/pod"
kubectl rollout restart deployment rp
echo "Finished processing template"
