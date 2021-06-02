#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
echo "Adding curl and jq"
apk --no-cache add curl jq

echo
echo "fetching kubectl"
curl -qL https://storage.googleapis.com/kubernetes-release/release/v1.20.0/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl

rpAdapterURL=https://adapter-rp.||DOMAIN||/relyingparties
callbackURL=https://demo-issuer.||DOMAIN||/oauth2/callback

registerRPTenant() {
    n=0

    # TODO implement a smart healthcheck on RP Adapter: https://github.com/trustbloc/edge-adapter/issues/134
    maxAttempts=60

    until [ $n -ge $maxAttempts ]
    do
        response=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" \
        --header "Content-Type: application/json" \
        --request POST \
        --data '{"label": "demo-issuer.||DOMAIN||", "callback": "'$callbackURL'", "scopes": ["driver_license:local","driver_license_evidence:remote"]}' \
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

echo "RP Tenant ClientID=$clientID Callback=$callbackURL Scopes=$scopes PublicDID=$publicDID"
echo ""

echo
config_map_name=$(kubectl get cm  -l component=issuer,group=demo  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep issuer-env)
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

grep -q '^ISSUER_OIDC_CLIENTID' ${config_map_env_file} &&  sed -i "s/^ISSUER_OIDC_CLIENTID.*/ISSUER_OIDC_CLIENTID=${clientID}/" ${config_map_env_file} || echo "ISSUER_OIDC_CLIENTID=${clientID}" >> ${config_map_env_file}
grep -q '^ISSUER_OIDC_CLIENTSECRET' ${config_map_env_file} &&  sed -i "s/^ISSUER_OIDC_CLIENTSECRET.*/ISSUER_OIDC_CLIENTSECRET=${clientSecret}/" ${config_map_env_file} || echo "ISSUER_OIDC_CLIENTSECRET=${clientSecret}" >> ${config_map_env_file}

echo "mutating configMap ${config_map_name}"
kubectl create cm ${config_map_name} --dry-run=client --from-env-file=${config_map_env_file} -o yaml > ${config_map}
echo
cat ${config_map}
echo
kubectl apply -f ${config_map}
echo "labeling"
kubectl label cm ${config_map_name} component=issuer group=demo project=trustbloc instance=||DEPLOYMENT_ENV||
echo "recycling issuer deployment/pod"
kubectl rollout restart deployment issuer
echo "Finished processing template"
