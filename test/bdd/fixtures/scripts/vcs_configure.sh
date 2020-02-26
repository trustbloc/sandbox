#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# CouchDB takes time to start up, so we will retry if trying to create a profile fails
n=0
maxAttempts=20

until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-1", "uri":"http://vc-issuer-1.com", "signatureType":"Ed25519Signature2018"}' \
   http://vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ]
   then
      break
   fi
   echo "Invalid 'created' field from response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   sleep 5
done

# Once the above call succeeds, we can assume that CouchDB is up.
# If it fails, then this should almost certainly fail too
curl -d '{"name":"vc-issuer-2", "uri":"http://vc-issuer-2.com", "signatureType":"Ed25519Signature2018", "did":"did:v1:test:nym:z6MkhLbRigh9utJNCaiEAdkqktz4r7yVBFDeaeqCeT7pRFnF","didPrivateKey":"5dF8yAW7hjLkJsfMXKqTPdDZUT56dX7Jq7TdXEtUEHHt2YUFAE34nQwyPCEp5XdWCKPSxs69xXqozsNh6MoJTmz5"}' -H "Content-Type: application/json" -X POST http://vcs.example.com:8070/profile
