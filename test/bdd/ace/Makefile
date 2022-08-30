# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

DEPLOYMENT_ENV           ?= local
DOMAIN                   ?= ${DEPLOYMENT_ENV}.trustbloc.dev
BLOC_DOMAIN		        ?= orb-1.${DOMAIN}
GATEKEEPER_HOST			?= gatekeeper.${DOMAIN}

.PHONY: all
all: clean bdd-test

.PHONY: bdd-test
bdd-test:
	GATEKEEPER_HOST=${GATEKEEPER_HOST} ORB_DOMAIN=${BLOC_DOMAIN} ORB_AUTH_TOKEN=ADMIN_TOKEN TAGS=gatekeeper_e2e \
	go test -count=1 -v -cover . -p 1 -timeout=10m -race

.PHONY: clean
clean:
	@rm -rf ./build
