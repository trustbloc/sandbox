#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
echo "Adding vendor profiles"

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"verseone-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":0,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-universalregistrar/driver-did-v1","options": {"ledger": "test", "keytype": "ed25519"}},"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile verseone-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from verseone-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create verseone-ed25519signature2018-ed25519 profile"
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
   --data '{"name":"elem-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR","signatureRepresentation":0,"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile elem-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from elem-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create elem-ed25519signature2018-ed25519 profile"
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
   --data '{"name":"sov-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":0,"uniRegistrar":{"driverURL":"https://uniregistrar.io/1.0/register?driverId=driver-universalregistrar/driver-did-sov","options": {"network":"danube"}},"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile sov-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from sov-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create sov-ed25519signature2018-ed25519 profile"
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
   --data '{"name":"didkey-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","didPrivateKey":"28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile didkey-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from didkey-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

  n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create didkey-ed25519signature2018-ed25519 profile"
     exit 1
   fi
   sleep 5
done

echo "Finished adding vendor profiles"
