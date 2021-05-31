#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding curl"
apk --no-cache add curl

vc_holder_interop=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
   --request POST \
   --data '{"name":"vc-holder-interop", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1, "didKeyType":"Ed25519"}' \
   --insecure https://holder-vcs.||DOMAIN||/holder/profile)

vc_holder_jsonwebsignature2020_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
   --request POST \
   --data '{"name":"vc-holder-jsonwebsignature2020-ed25519", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1, "didKeyType":"Ed25519"}' \
    --insecure https://holder-vcs.||DOMAIN||/holder/profile)


vc_holder_jsonwebsignature2020_p256=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
   --request POST \
   --data '{"name":"vc-holder-jsonwebsignature2020-p256", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1, "didKeyType":"P256"}' \
   --insecure https://holder-vcs.||DOMAIN||/holder/profile)


vc_holder_didkey=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
   --request POST \
   --data '{"name":"vc-holder-didkey", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"did":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","didPrivateKey":"28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs","didKeyID":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd", "didKeyType":"Ed25519"}' \
   --insecure https://holder-vcs.||DOMAIN||/holder/profile)


# TODO driver-did-v1 latest not working
#vc_holder_didv1=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
#   --request POST \
#   --data '{"name":"vc-holder-didv1", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.||DOMAIN||/1.0/register?driverId=driver-universalregistrar/driver-did-v1"}, "didKeyType":"Ed25519"}' \
#   --insecure https://holder-vcs.||DOMAIN||/holder/profile)

# TODO enable it
#vc_holder_didsov=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
#   --request POST \
#   --data '{"name":"vc-holder-didsov", "signatureType":"Ed25519Signature2018","signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uniregistrar.io/1.0/register?driverId=driver-universalregistrar/driver-did-sov","options": {"network":"danube"}},"didKeyType":"Ed25519"}' \
#   --insecure https://holder-vcs.||DOMAIN||/holder/profile)


vc_holder_didelem=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_holder_rw_token" \
   --request POST \
   --data '{"name":"vc-holder-didelem", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR","didKeyID":"did:elem:ropsten:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ#SQ2PY2xs7NOr6B26xq_pJMNpuYk6dOeROlkzKF7909I", "didKeyType":"Ed25519"}' \
  --insecure https://holder-vcs.||DOMAIN||/holder/profile)

checkProfileIsCreated()
{
   if [ "$1" == "201" ] || [ "$1" == "400" ]
   then
     echo "holder profile $2 is created"
   else
     echo "failed create holder profile $2 response code $1"
     exit 1
   fi
}

checkProfileIsCreated $vc_holder_interop vc-holder-interop
checkProfileIsCreated $vc_holder_jsonwebsignature2020_ed25519 vc-holder-jsonwebsignature2020-ed25519
checkProfileIsCreated $vc_holder_jsonwebsignature2020_p256 vc-holder-jsonwebsignature2020-p256
checkProfileIsCreated $vc_holder_didkey vc-holder-didkey
#checkProfileIsCreated $vc_holder_didv1 vc-holder-didv1
#checkProfileIsCreated $vc_holder_didsov vc-holder-didsov
checkProfileIsCreated $vc_holder_didelem vc-holder-didelem
