#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

echo "Adding verifier profiles"
n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer vcs_verifier_rw_token" \
   --request POST \
   --data '{"id":"verifier1","name":"Verifier", "credentialChecks":["proof","status"], "presentationChecks":["proof"]}' \
   http://rp.vcs.example.com:8069/verifier/profile | jq -r '.id' 2>/dev/null)
   echo "'created' field from profile verfier1 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from verfier1 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create verfier1 profile"
     exit 1
   fi
   sleep 5
done

echo "Finished adding verifier profiles"
