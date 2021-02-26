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

# configure comparator
revAgencyComparatorConfig=$(.build/bin/demo comparator getConfig https://rev-agency-comparator.trustbloc.local)
revAgencyComparatorConfigDID=$(echo "${revAgencyComparatorConfig}" | jq -r '.did')
revAgencyComparatorConfigPrivateKey=$(echo "${revAgencyComparatorConfig}" | jq -r '.privateKey')
revAgencyComparatorConfigKeyID=$(echo "${revAgencyComparatorConfig}" | jq -r '.keyID')

# create vc issuer profile
vc_issuer_rev_agency=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-rev-agency", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${revAgencyComparatorConfigDID}"'","didPrivateKey":"'"${revAgencyComparatorConfigPrivateKey}"'","didKeyID":"'"${revAgencyComparatorConfigKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

response=${vc_issuer_rev_agency//RESPONSE_CODE*/}
code=${vc_issuer_rev_agency//*RESPONSE_CODE=/}

validateProfileCreation $code $response vc_issuer vc_issuer_rev_agency

# configure comparator
empDeptComparatorConfig=$(.build/bin/demo comparator getConfig https://emp-dept-comparator.trustbloc.local)
empDeptComparatorConfigDID=$(echo "${empDeptComparatorConfig}" | jq -r '.did')
empDeptComparatorConfigPrivateKey=$(echo "${empDeptComparatorConfig}" | jq -r '.privateKey')
empDeptComparatorConfigKeyID=$(echo "${empDeptComparatorConfig}" | jq -r '.keyID')

# create vc issuer profile
vc_issuer_emp_dept=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-emp-dept", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${empDeptComparatorConfigDID}"'","didPrivateKey":"'"${empDeptComparatorConfigPrivateKey}"'","didKeyID":"'"${empDeptComparatorConfigKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

response=${vc_issuer_emp_dept//RESPONSE_CODE*/}
code=${vc_issuer_emp_dept//*RESPONSE_CODE=/}

validateProfileCreation $code $response vc_issuer vc_issuer_emp_dept

# create client with uscis (Utopia Citizenship and Immigration) agent
cbp_dept_act_linking_client=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"did":"'"${empDeptComparatorConfigDID}"'", "callback":"https://cbp-rp.trustbloc.local"}' \
   --insecure https://uscis-rp.trustbloc.local/client)

response=${cbp_dept_act_linking_client//RESPONSE_CODE*/}
code=${cbp_dept_act_linking_client//*RESPONSE_CODE=/}
clientID=$(echo $response | jq -r .clientID)
clientSecret=$(echo $response | jq -r .clientSecret)

validateProfileCreation $code $response ace_rp_client cbp_dept_act_linking_client

# create profile for uscis_profile_at_cbp
uscis_profile_at_cbp=$(curl -o /dev/null -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"id":"uscis-profile", "name":"Utopia Citizen and Immigration", "url":"https://uscis-rp.trustbloc.local", "clientID":"'"${clientID}"'", "clientSecret":"'"${clientSecret}"'", "did":"'"${empDeptComparatorConfigDID}"'", "callback":"vc-issuer-emp-dept"}' \
   --insecure https://cbp-rp.trustbloc.local/profile)

response=${uscis_profile_at_cbp//RESPONSE_CODE*/}
code=${uscis_profile_at_cbp//*RESPONSE_CODE=/}

validateProfileCreation $code $response ace_rp_profile uscis_profile_at_cbp
