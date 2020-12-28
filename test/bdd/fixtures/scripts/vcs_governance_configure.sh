#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)

trustbloc_governance=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_governance_rw_token" \
   --request POST \
   --data '{"name":"governance", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   https://governance-vcs.trustbloc.local/governance/profile)

checkProfileIsCreated()
{
   if [ "$1" == "201" ]
   then
     echo "${GREEN} governance profile $2 is created"
     tput init
   else
     echo "${RED}failed create governance profile $2 response code $1"
     tput init
     exit -1
   fi
}

checkProfileIsCreated $trustbloc_governance trustbloc-governance
