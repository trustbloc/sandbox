#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

echo "Adding Issuer Adapter profiles"

n=0
maxAttempts=60
until [ $n -ge $maxAttempts ]
do
   response=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-cc-issuer", "name":"TrustBloc - Credit Card Data Issuer", "url": "https://demo-issuer.||DOMAIN||/didcomm", "oidcProvider": "https://hydra.||DOMAIN||/", "credScopes":["CreditCardStatement"],  "supportedVCContexts" : ["https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld"]}' \
   --insecure http://adapter-issuer/profile 2>/dev/null)
   echo "'created' field from profile tb-cc-issuer response is: $response"

   responseCreatedTime=$(echo ${response} | jq -r '.createdAt' 2>/dev/null )
   responseError=$(echo ${response} | jq -r '.errMessage' 2>/dev/null )

   if [ -n "$(echo ${responseError} | grep 'already exists')" ]
   then
      break
   fi

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

n=0
maxAttempts=60
until [ $n -ge $maxAttempts ]
do
   response=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-cr-issuer", "name":"TrustBloc - Credit Report Issuer", "url":"https://demo-issuer.||DOMAIN||/didcomm", "oidcProvider":"https://hydra.||DOMAIN||/", "credScopes":["CreditScore"], "supportedVCContexts" : ["https://trustbloc.github.io/context/vc/examples/credit-score-v1.jsonld"], "requiresBlindedRoute": true}' \
   --insecure http://adapter-issuer/profile 2>/dev/null)
   echo "'created' field from profile tb-cr-issuer response is: $response"

   responseCreatedTime=$(echo ${response} | jq -r '.createdAt' 2>/dev/null )
   responseError=$(echo ${response} | jq -r '.errMessage' 2>/dev/null )

   if [ -n "$(echo ${responseError} | grep 'already exists')" ]
   then
      break
   fi

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'id' field in the response when trying to create tb-cr-issuer profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create tb-cr-issuer profile"
     exit 1
   fi
   sleep 5
done

n=0
until [ $n -ge $maxAttempts ]
do
   response=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-dl-issuer", "name":"TrustBloc - Driving License + Assurance Issuer", "url":"https://demo-issuer.||DOMAIN||/didcomm", "oidcProvider":"https://hydra.||DOMAIN||/", "credScopes":["mDL"], "supportedVCContexts" : ["https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld"], "supportsAssuranceCredential" : true, "requiresBlindedRoute": true}' \
   --insecure http://adapter-issuer/profile 2>/dev/null)
   echo "'created' field from profile tb-dl-issuer response is: $response"

   responseCreatedTime=$(echo ${response} | jq -r '.createdAt' 2>/dev/null )
   responseError=$(echo ${response} | jq -r '.errMessage' 2>/dev/null )

   if [ -n "$(echo ${responseError} | grep 'already exists')" ]
   then
      break
   fi

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

n=0
until [ $n -ge $maxAttempts ]
do
   response=$(curl -k --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"tb-prc-issuer", "name":"TrustBloc - Permanent Resident Card Issuer", "url":"https://demo-issuer.||DOMAIN||/didcomm", "oidcProvider":"https://hydra.||DOMAIN||/", "credScopes":["PermanentResidentCard"], "supportedVCContexts" : ["https://w3id.org/citizenship/v1"], "supportsWACI" : true, "linkedWallet":"https://wallet.||DOMAIN||/waci"}' \
   --insecure http://adapter-issuer/profile 2>/dev/null)
   echo "'created' field from profile tb-prc-issuer response is 2: $response"

   responseCreatedTime=$(echo ${response} | jq -r '.createdAt' 2>/dev/null )
   responseError=$(echo ${response} | jq -r '.errMessage' 2>/dev/null )

   if [ -n "$(echo ${responseError} | grep 'already exists')" ]
   then
      break
   fi

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'id' field in the response when trying to create tb-prc-issuer profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create tb-prc-issuer profile"
     exit 1
   fi
   sleep 5
done

echo "Finished adding Issuer Adapter profiles"
