#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding curl"
apk --no-cache add curl


trustbloc_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_verifier_rw_token" \
   --request POST \
   --data '{"id":"trustbloc-verifier","name":"Verifier", "credentialChecks":["proof","credentialStatus"], "presentationChecks":["proof","credentialStatus"]}' \
   --insecure https://verifier-vcs.||DOMAIN||/verifier/profile)

interop_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_verifier_rw_token" \
   --request POST \
   --data '{"id":"vc-verifier-interop","name":"Verifier", "credentialChecks":["proof","credentialStatus"], "presentationChecks":["proof","credentialStatus"]}' \
   --insecure https://verifier-vcs.||DOMAIN||/verifier/profile)

checkProfileIsCreated()
{
   if [ "$1" == "201" ] || [ "$1" == "400" ]
   then
     echo "verifier profile $2 is created"
   else
     echo "failed create verifier profile $2 response code $1"
     exit 1
   fi
}

checkProfileIsCreated $trustbloc_ed25519signature2018_ed25519 trustbloc-ed5519signature2018-ed25519
checkProfileIsCreated $interop_ed25519signature2018_ed25519 interop_ed25519signature2018_ed25519
