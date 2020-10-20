#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


echo "Adding issuer trustbloc profiles"


n=0
maxAttempts=40
while true
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile trustbloc-ed25519signature2018-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from trustbloc-ed25519signature2018-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."


   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create trustbloc-ed25519signature2018-ed25519 profile"
     exit 1
   fi
   sleep 5
done


n=0
maxAttempts=40
while true
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-jsonwebsignature2020-ed25519", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"Ed25519"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile trustbloc-jsonwebsignature2020-ed25519 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from trustbloc-jsonwebsignature2020-ed25519 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create trustbloc-jsonwebsignature2020-ed25519 profile"
     exit 1
   fi
   sleep 5
done

n=0
maxAttempts=40
while true
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-jsonwebsignature2020-p256", "uri":"http://vc-issuer-p256.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"P256"}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile trustbloc-jsonwebsignature2020-p256 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from trustbloc-jsonwebsignature2020-p256 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create trustbloc-jsonwebsignature2020-p256 profile"
     exit 1
   fi
   sleep 5
done


echo "Finished adding trustbloc profiles"
