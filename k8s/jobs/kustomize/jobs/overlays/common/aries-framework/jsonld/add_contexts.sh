#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl

ENDPOINTS="adapter-issuer adapter-rp issuer-vcs verifier-vcs issuer ucis-rp cbp-rp benefits-dept-rp";
for endpoint in ${ENDPOINTS};
do
   n=0
   maxAttempts=3
   until [ $n -ge $maxAttempts ]
   do
      echo "Adding JSON-LD contexts for ${endpoint}..."

      response=$(curl -k --header "Content-Type: application/json" \
      --request POST \
      --data @opt/..data/contexts_payload.json \
      --insecure http://${endpoint}/context/add 2>/dev/null)

      if [ "$response" = "{}" ]
      then
         echo "DONE"
         break
      fi

      echo "ERROR"
      echo $response

      n=$((n+1))
      if [ $n -eq $maxAttempts ]
      then
        echo "Failed to add JSON-LD contexts for ${endpoint}"
      fi
      sleep 5
   done;
done;
