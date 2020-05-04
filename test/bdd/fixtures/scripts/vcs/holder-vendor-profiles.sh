#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding holder(vendor) profiles"

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-holder-didkey", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"did":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","didPrivateKey":"28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs", "didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-didkey response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-didkey response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-didkey"
     exit 1
   fi
   sleep 5
done

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-holder-didv1", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-universalregistrar/driver-did-v1"}, "didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-didv1 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-didv1 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-didv1"
     exit 1
   fi
   sleep 5
done

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-holder-didsov", "signatureType":"Ed25519Signature2018","signatureRepresentation":0,"uniRegistrar":{"driverURL":"https://uniregistrar.io/1.0/register?driverId=driver-universalregistrar/driver-did-sov","options": {"network":"danube"}},"didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-didsov response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-didsov response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-didsov"
     exit 1
   fi
   sleep 5
done

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-holder-didelem", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR", "didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-didelem response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-didelem response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-didelem"
     exit 1
   fi
   sleep 5
done

echo "Finished adding holder(vendor) profiles"
