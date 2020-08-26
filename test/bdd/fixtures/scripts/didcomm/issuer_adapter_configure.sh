#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

echo "Adding Issuer Adapter profiles"

n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-cc-issuer", "name":"TrustBloc - Credit Card Data Issuer", "url":"https://issuer.trustbloc.local/didcomm", "supportedVCContexts" : ["https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld","https://trustbloc.github.io/context/vc/examples/credit-score-v1.jsonld"]}' \
   https://issuer.adapter.rest.example.com:10061/profile | jq -r '.createdAt' 2>/dev/null)
   echo "'created' field from profile tb-cc-issuer response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'id' field in the response when trying to create tb-cc-issuer profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create tb-cc-issuer profile"
     exit 1
   fi
   sleep 5
done
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-dl-issuer", "name":"TrustBloc - Driving License + Evidence Issuer", "url":"https://issuer.trustbloc.local/didcomm", "supportedVCContexts" : ["https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld"], "supportsAssuranceCredential" : true}' \
   https://issuer.adapter.rest.example.com:10061/profile | jq -r '.createdAt' 2>/dev/null)
   echo "'created' field from profile tb-dl-issuer response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'id' field in the response when trying to create tb-dl-issuer profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create tb-dl-issuer profile"
     exit 1
   fi
   sleep 5
done

echo "Finished adding Issuer Adapter profiles"
