#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)


checkProfileIsCreated()
{
   if [ "$1" == "201" ]
   then
     echo "${GREEN} issuer profile $2 is created"
     tput init
   else
     echo "${RED}failed create issuer profile $2 response code $1"
     tput init
     exit -1
   fi
}

trustbloc_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

trustbloc_jsonwebsignature2020_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-jsonwebsignature2020-ed25519", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

trustbloc_jsonwebsignature2020_p256=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"trustbloc-jsonwebsignature2020-p256", "uri":"http://vc-issuer-p256.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"didKeyType":"P256"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)


interop_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"interop-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)


interop_jsonwebsignature2020_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"interop-jsonwebsignature2020-ed25519", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)


interop_jsonwebsignature2020_p256=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"interop-jsonwebsignature2020-p256", "uri":"http://example.com", "signatureType":"JsonWebSignature2020", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"disableVCStatus":true,"didKeyType":"P256"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

vc_issuer_interop_key=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-interop-key", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","didPrivateKey":"28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs","didKeyID":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd","signatureRepresentation":1,"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)


vc_issuer_interop=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"vc-issuer-interop", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-did-method-rest"},"disableVCStatus":false,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)


# TODO driver-did-v1 latest not working
#verseone_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
#   --request POST \
#   --data '{"name":"verseone-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uni-registrar-web.trustbloc.local/1.0/register?driverId=driver-universalregistrar/driver-did-v1","options": {"ledger": "test", "keytype": "ed25519"}},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
#   --insecure https://issuer-vcs.trustbloc.local/profile)


elem_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"elem-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR","didKeyID":"did:elem:ropsten:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ#SQ2PY2xs7NOr6B26xq_pJMNpuYk6dOeROlkzKF7909I","signatureRepresentation":1,"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

# TODO enable it
#sov_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
#   --request POST \
#   --data '{"name":"sov-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018","signatureRepresentation":1,"uniRegistrar":{"driverURL":"https://uniregistrar.io/1.0/register?driverId=driver-universalregistrar/driver-did-sov","options": {"network":"danube"}},"disableVCStatus":true,"didKeyType":"Ed25519"}' \
#   --insecure https://issuer-vcs.trustbloc.local/profile)

didkey_ed25519signature2018_ed25519=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"didkey-ed25519signature2018-ed25519", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"did:key:z6MkjtF2htvLuxPu3wAuVgu1zZ5Jgwvu7QkJkyvyGX478RrM","didPrivateKey":"5k9LgFFpxYCrHKyKxZWj6CWZNs6rFkPfQiggMUCwRBifjP4wLXZaFuFr1vhwK7Kj9YLowXZr3tQvwpLDonXBJUpm","didKeyID":"did:key:z6MkjtF2htvLuxPu3wAuVgu1zZ5Jgwvu7QkJkyvyGX478RrM#z6MkjtF2htvLuxPu3wAuVgu1zZ5Jgwvu7QkJkyvyGX478RrM","signatureRepresentation":1,"disableVCStatus":true,"didKeyType":"Ed25519"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

didkey_BbsBlsSignature2020_bls12381G2=$(curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
   --request POST \
   --data '{"name":"didkey-bbsblssignature2020-bls12381g2", "uri":"http://example.com", "signatureType":"BbsBlsSignature2020", "did":"did:key:zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ","didPrivateKey":"6gsgGpdx7p1nYoKJ4b5fKt1xEomWdnemg9nJFX6mqNCh","didKeyID":"did:key:zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ#zUC72c7u4BYVmfYinDceXkNAwzPEyuEE23kUmJDjLy8495KH3pjLwFhae1Fww9qxxRdLnS2VNNwni6W3KbYZKsicDtiNNEp76fYWR6HCD8jAz6ihwmLRjcHH6kB294Xfg1SL1qQ","signatureRepresentation":0,"didKeyType":"BLS12381G2"}' \
   --insecure https://issuer-vcs.trustbloc.local/profile)

checkProfileIsCreated $trustbloc_ed25519signature2018_ed25519 trustbloc-ed5519signature2018-ed25519
checkProfileIsCreated $trustbloc_jsonwebsignature2020_ed25519 trustbloc-jsonwebsignature2020-ed25519
checkProfileIsCreated $trustbloc_jsonwebsignature2020_p256 trustbloc-jsonwebsignature2020-p256
checkProfileIsCreated $interop_ed25519signature2018_ed25519 interop-ed25519signature2018-ed25519
checkProfileIsCreated $interop_jsonwebsignature2020_ed25519 interop-jsonwebsignature2020-ed25519
checkProfileIsCreated $interop_jsonwebsignature2020_p256 interop-jsonwebsignature2020-p256
checkProfileIsCreated $vc_issuer_interop_key vc-issuer-interop-key
checkProfileIsCreated $vc_issuer_interop vc-issuer-interop
#checkProfileIsCreated $verseone_ed25519signature2018_ed25519 verseone-ed25519signature2018-ed25519
checkProfileIsCreated $elem_ed25519signature2018_ed25519 elem-ed25519signature2018-ed25519
#checkProfileIsCreated $sov_ed25519signature2018_ed25519 sov-ed25519signature2018-ed25519
checkProfileIsCreated $didkey_ed25519signature2018_ed25519 didkey-ed25519signature2018-ed25519
checkProfileIsCreated $didkey_BbsBlsSignature2020_bls12381G2 didkey-bbsblssignature2020-bls12381g2

