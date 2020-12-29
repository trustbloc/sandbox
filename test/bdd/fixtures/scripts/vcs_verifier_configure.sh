#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)


trustbloc_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_verifier_rw_token" \
   --request POST \
   --data '{"id":"verifier1","name":"Verifier", "credentialChecks":["proof","status"], "presentationChecks":["proof"]}' \
   --insecure https://rp-vcs.trustbloc.local/verifier/profile)

checkProfileIsCreated()
{
   if [ "$1" == "201" ]
   then
     echo "${GREEN} verifier profile $2 is created"
     tput init
   else
     echo "${RED}failed create verifier profile $2 response code $1"
     tput init
     exit -1
   fi
}

checkProfileIsCreated $trustbloc_ed25519signature2018_ed25519 trustbloc-ed5519signature2018-ed25519
