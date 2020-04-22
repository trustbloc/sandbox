#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding interop profiles"
n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"interop-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile interop-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from interop-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create interop-ed25519signature2018-ed25519 profile"
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
   --data '{"name":"interop-jsonwebsignature2020-ed25519", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile interop-jsonwebsignature2020-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from interop-jsonwebsignature2020-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create interop-jsonwebsignature2020-ed25519 profile"
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
   --data '{"name":"interop-jsonwebsignature2020-p256", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"P256"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile interop-jsonwebsignature2020-p256 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from interop-jsonwebsignature2020-p256 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create interop-jsonwebsignature2020-p256 profile"
     exit 1
   fi
   sleep 5
done

echo "Finished adding interop profiles"
