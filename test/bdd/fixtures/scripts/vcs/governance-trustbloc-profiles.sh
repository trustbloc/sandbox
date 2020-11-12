#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


apk --no-cache add curl jq


echo "Adding governance profiles"


n=0
maxAttempts=60
while true
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer vcs_governance_rw_token" \
   --request POST \
   --data '{"name":"governance", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   http://governance.vcs.example.com:8066/governance/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile governance response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ] && [ "$responseCreatedTime" != "null" ]
   then
      break
   fi
   echo "Invalid 'created' field from governance response when trying to create a profile (attempt $((n+1))/$maxAttempts)."


   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "failed to create governance profile"
     exit 1
   fi
   sleep 5
done
