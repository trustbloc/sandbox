#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding holder(trustbloc) profiles"

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-holder-interop", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"}, "didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-interop response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-interop response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-interop"
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
   --data '{"name":"vc-holder-jsonwebsignature2020-ed25519", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"}, "didKeyType":"Ed25519"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-jsonwebsignature2020-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-jsonwebsignature2020-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-jsonwebsignature2020-ed25519"
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
   --data '{"name":"vc-holder-jsonwebsignature2020-p256", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"}, "didKeyType":"P256"}' \
   http://holder.vcs.example.com:8067/holder/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile vc-holder-jsonwebsignature2020-p256 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from vc-holder-jsonwebsignature2020-p256 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create holder profile : vc-holder-jsonwebsignature2020-p256"
     exit 1
   fi
   sleep 5
done

echo "Finished adding holder(trustbloc) profiles"
