#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)


validateProfileCreation()
{
   if [ "$1" == "201" ]
   then
     echo "${GREEN} $3 profile $4 is created"
     tput init
   else
     echo "${RED}failed create $2 profile $4 response code $1 - $2"
     tput init
     exit -1
   fi
}

# uscis - configure comparator
uscisComparatorConfig=$(.build/bin/demo comparator getConfig https://uscis-comparator.trustbloc.local)
uscisComparatorConfigDID=$(echo "${uscisComparatorConfig}" | jq -r '.did')
uscisComparatorConfigPrivateKey=$(echo "${uscisComparatorConfig}" | jq -r '.privateKey')
uscisComparatorConfigKeyID=$(echo "${uscisComparatorConfig}" | jq -r '.keyID')

# uscis - create vc issuer profile
vc_issuer_uscis=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-uscis", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${uscisComparatorConfigDID}"'","didPrivateKey":"'"${uscisComparatorConfigPrivateKey}"'","didKeyID":"'"${uscisComparatorConfigKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

response=${vc_issuer_uscis//RESPONSE_CODE*/}
code=${vc_issuer_uscis//*RESPONSE_CODE=/}

validateProfileCreation $code $response vc_issuer vc_issuer_uscis

# cbp - configure comparator
cbpComparatorConfig=$(.build/bin/demo comparator getConfig https://cbp-comparator.trustbloc.local)
cbpComparatorConfigDID=$(echo "${cbpComparatorConfig}" | jq -r '.did')
cbpComparatorConfigPrivateKey=$(echo "${cbpComparatorConfig}" | jq -r '.privateKey')
cbpComparatorConfigKeyID=$(echo "${cbpComparatorConfig}" | jq -r '.keyID')

# cbp - create vc issuer profile
vc_issuer_cbp=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-cbp", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${cbpComparatorConfigDID}"'","didPrivateKey":"'"${cbpComparatorConfigPrivateKey}"'","didKeyID":"'"${cbpComparatorConfigKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

response=${vc_issuer_cbp//RESPONSE_CODE*/}
code=${vc_issuer_cbp//*RESPONSE_CODE=/}

validateProfileCreation $code $response vc_issuer vc_issuer_cbp

# benefits-dept - configure comparator
benefitsDeptComparatorConfig=$(.build/bin/demo comparator getConfig https://benefits-dept-comparator.trustbloc.local)
benefitsDeptComparatorConfigDID=$(echo "${benefitsDeptComparatorConfig}" | jq -r '.did')
benefitsDeptComparatorConfigPrivateKey=$(echo "${benefitsDeptComparatorConfig}" | jq -r '.privateKey')
benefitsDeptComparatorConfigKeyID=$(echo "${benefitsDeptComparatorConfig}" | jq -r '.keyID')

# benefits-dept - create vc issuer profile
vc_issuer_benefits_dept=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-benefits-dept", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${benefitsDeptComparatorConfigDID}"'","didPrivateKey":"'"${benefitsDeptComparatorConfigPrivateKey}"'","didKeyID":"'"${benefitsDeptComparatorConfigKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

response=${vc_issuer_benefits_dept//RESPONSE_CODE*/}
code=${vc_issuer_benefits_dept//*RESPONSE_CODE=/}

validateProfileCreation $code $response vc_issuer vc_issuer_benefits_dept

# create client with uscis (Utopia Citizenship and Immigration) agent
cbp_dept_act_linking_client=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"did":"'"${cbpComparatorConfigDID}"'", "callback":"https://cbp-rp.trustbloc.local"}' \
   --insecure https://uscis-rp.trustbloc.local/client)

response=${cbp_dept_act_linking_client//RESPONSE_CODE*/}
code=${cbp_dept_act_linking_client//*RESPONSE_CODE=/}
clientID=$(echo $response | jq -r .clientID)
clientSecret=$(echo $response | jq -r .clientSecret)

validateProfileCreation $code $response ace_rp_client cbp_dept_act_linking_client

# create profile for uscis_profile_at_cbp
uscis_profile_at_cbp=$(curl -o /dev/null -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"uscis-profile", "name":"Utopia Citizen and Immigration", "url":"https://uscis-rp.trustbloc.local", "clientID":"'"${clientID}"'", "clientSecret":"'"${clientSecret}"'", "did":"'"${cbpComparatorConfigDID}"'"}' \
   --insecure https://cbp-rp.trustbloc.local/profile)

response=${uscis_profile_at_cbp//RESPONSE_CODE*/}
code=${uscis_profile_at_cbp//*RESPONSE_CODE=/}

validateProfileCreation $code $response ace_rp_profile uscis_profile_at_cbp

# create extractor profile for benefits at uscis
benefits_dept_profile_at_uscis=$(curl -o /dev/null -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"benefit-dept-profile", "name":"Benefits Settlement Department", "url":"https://benefits-dept-rp.trustbloc.local", "did":"'"${benefitsDeptComparatorConfigDID}"'"}' \
   --insecure https://uscis-rp.trustbloc.local/profile)

response=${benefits_dept_profile_at_uscis//RESPONSE_CODE*/}
code=${benefits_dept_profile_at_uscis//*RESPONSE_CODE=/}

validateProfileCreation $code $response ace_rp_profile benefits_dept_profile_at_uscis
