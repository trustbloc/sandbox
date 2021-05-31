#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding curl"
apk --no-cache add curl

trustbloc_governance=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_governance_rw_token" \
   --request POST \
   --data '{"name":"governance", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://governance-vcs.||DOMAIN||/governance/profile)

checkProfileIsCreated()
{
   if [ "$1" == "201" ] || [ "$1" == "400" ]
   then
     echo "governance profile $2 is created"
   else
     echo "failed create governance profile $2 response code $1"
     exit 1
   fi
}

checkProfileIsCreated $trustbloc_governance trustbloc-governance
