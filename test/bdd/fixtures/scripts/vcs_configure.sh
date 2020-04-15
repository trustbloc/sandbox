#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq


# CouchDB takes time to start up, so we will retry if trying to create a profile fails

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-1", "uri":"http://vc-issuer-1.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-did-method-rest"}}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer1 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer1 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   sleep 5
done


n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-2", "uri":"http://vc-issuer-2.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":0,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-universalregistrar/driver-did-v1","options": {"ledger": "test", "keytype": "ed25519"}}}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer2 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer2 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done

n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-3", "uri":"http://vc-issuer-3.com", "signatureType":"Ed25519Signature2018", "did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR","signatureRepresentation":0}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer3 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer3 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done

n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-4", "uri":"http://vc-issuer-4.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":0,"uniRegistrar":{"driverURL":"https://uniregistrar.io/1.0/register?driver-universalregistrar/driver-did-sov","options": {"network":"danube"}}}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer4 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer4 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done


n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-interop", "uri":"http://vc-issuer-interop.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-did-method-rest"},"disableVCStatus":true}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer-interop response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer-interop response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   sleep 5
done

n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-didkey", "uri":"http://vc-issuer-didkey.com", "signatureType":"Ed25519Signature2018", "did":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","didPrivateKey":"28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs","signatureRepresentation":1}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer-didkey response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer-didkey response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   sleep 5
done
