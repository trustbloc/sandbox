# Copyright Avast Software.
#
# SPDX-License-Identifier: Apache-2.0

DEPLOYMENT_ENV           			?= local
DOMAIN                   			?= ${DEPLOYMENT_ENV}.trustbloc.dev
BLOC_DOMAIN		        			?= orb-1.${DOMAIN}
ISSUER_PRE_AUTHORIZE_URL			?= https://demo-issuer.${DOMAIN}/pre-authorize
CONTEXT_PROVIDER_URL				?= https://static-file-server.${DOMAIN}/ld-contexts.json
DID_DOMAIN 							?= https://${BLOC_DOMAIN}
DID_SERVICE_AUTH_TOKEN 				?= ADMIN_TOKEN
UNI_RESOLVER_URL					?= https://did-resolver.${DOMAIN}/1.0/identifiers


.PHONY: all
all: clean bdd-test

.PHONY: bdd-test
bdd-test:
	ISSUER_PRE_AUTHORIZE_URL=${ISSUER_PRE_AUTHORIZE_URL} CONTEXT_PROVIDER_URL=${CONTEXT_PROVIDER_URL} DID_DOMAIN=${DID_DOMAIN} \
	DID_SERVICE_AUTH_TOKEN=${DID_SERVICE_AUTH_TOKEN} UNI_RESOLVER_URL=${UNI_RESOLVER_URL} INSECURE_TLS=true \
	VC_FORMAT=jwt_vc_json-ld VC_TYPE=VerifiedEmployee DID_METHOD=jwk DID_KEY_TYPE=ECDSAP384DER \
	go test -count=1 -v -cover . -p 1 -timeout=3m -race

.PHONY: clean
clean:
	@rm -rf ./build
