#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

SHELL                       := /bin/bash
CONTAINER_CMD         	 	?= docker
USER_ID                          = $(shell id -u)
DOCKER_CMD_RUN_OPTS            ?= -u $(USER_ID)
CONTAINER_CMD_RUN_OPTS         ?= $(if $(findstring docker,$(CONTAINER_CMD)),$(DOCKER_CMD_RUN_OPTS),)

export DEPLOYMENT_ENV	?= local
# space delimited of Key:Value pairs
COMMON_LABELS		:= instance:${DEPLOYMENT_ENV}
export DOMAIN      		?= ${DEPLOYMENT_ENV}.trustbloc.dev
export HYDRA_POSTGRES_DSN								?= postgres://loginconsent:loginconsent-secret-pw@postgres-demo:5432/loginconsent?sslmode=disable

OS 				= $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH  				= $(shell uname -m | sed 's/x86_64/amd64/')

#IMAGES
LOGIN_CONSENT_IMG				?= ghcr.io/trustbloc-cicd/sandbox-login-consent-server:0.1.9-snapshot-bc094bb
HYDRA_IMG			?= oryd/hydra:v1.3.2-alpine

# do not modify
KUSTOMIZE_DIR       	= kustomize/login-consent
CERTS_OUTPUT_DIR      	 	= ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/certs
PREFIX							?=
KUSTOMIZE_BUILD_OPTS			?= --load-restrictor LoadRestrictionsNone --enable-alpha-plugins
export KUSTOMIZE_PLUGIN_HOME						= $(abspath .)/kustomize/plugin

.PHONY: all
all: setup

.PHONY: setup
setup: generate-test-certs
	@echo setup

.PHONY: setup-no-certs
setup-no-certs:
	@echo setup-no-certs

# TODO (#1539): frapsoft/openssl only has an amd64 version. While this does work when using Docker on arm64-based macOS
#              currently thanks to the automatic built-in QEMU emulation, it would be better to use a
#              native arm64 version.
.PHONY: generate-test-certs
generate-test-certs: clean-certs
	@echo $(abspath .)
	@$(CONTAINER_CMD) run ${CONTAINER_CMD_RUN_OPTS} -i --platform linux/amd64 --rm \
		-v $(abspath .):/opt/workspace:Z \
		-e DOMAIN=${DOMAIN} \
		-e CERTS_OUTPUT_DIR=${CERTS_OUTPUT_DIR} \
		--entrypoint "/opt/workspace/scripts/generate_test_certs.sh" \
		docker.io/frapsoft/openssl:latest
	@cd ${CERTS_OUTPUT_DIR} && ln -fs trustbloc-dev-ca.crt ca.crt
	@cd ${CERTS_OUTPUT_DIR} && ln -fs ${DOMAIN}.key tls.key
	@cd ${CERTS_OUTPUT_DIR} && ln -fs ${DOMAIN}.crt tls.crt

.PHONY: deploy
deploy: prechecks kustomize kubectl set-images set-labels deploy-login-consent

.PHONY: prechecks
prechecks:
ifeq (, $(shell stat ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} 2>/dev/null))
	@echo "Environment not found ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}"
	@exit 1
endif

.PHONY: set-labels
set-labels: kustomize
	@pushd ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} &&\
		${KUSTOMIZE} edit set label ${COMMON_LABELS} &&\
		popd

.PHONY: set-images
set-images: kustomize
	@pushd ${KUSTOMIZE_DIR}/base &&\
	${KUSTOMIZE} edit set image login-consent-server=${LOGIN_CONSENT_IMG} &&\
	popd
	@pushd ${KUSTOMIZE_DIR}/components/hydra &&\
	${KUSTOMIZE} edit set image hydra=${HYDRA_IMG} &&\
	popd

.PHONY: deploy-login-consent
deploy-login-consent: prechecks kustomize kubectl
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: prechecks kustomize kubectl set-images set-labels undeploy-login-consent

.PHONY: undeploy-login-consent
undeploy-login-consent: prechecks kustomize kubectl
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} | $(KUBECTL) delete -f -

.PHONY: kustomize
kustomize:
ifeq (, $(shell which kustomize 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p bin ;\
	curl -sSLo - https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v4.3.0/kustomize_v4.3.0_$(OS)_$(ARCH).tar.gz | tar xzf - -C bin/ ;\
	}
KUSTOMIZE=$(realpath ./bin/kustomize)
else
KUSTOMIZE=$(shell which kustomize)
endif

.PHONY: kubectl
kubectl:
ifeq (, $(shell which kubectl 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p bin ;\
	curl -sSL https://storage.googleapis.com/kubernetes-release/release/v1.21.2/bin/$(OS)/$(ARCH)/kubectl -o bin/kubectl ;\
  chmod u+x bin/kubectl ;\
	}
KUBECTL=$(realpath ./bin/kubectl)
else
KUBECTL=$(shell which kubectl)
endif

.PHONY: clean
clean: clean-all

.PHONY: clean-all
clean-all: clean-certs

.PHONY: clean-certs
clean-certs:
	@rm -Rf ${CERTS_OUTPUT_DIR}
