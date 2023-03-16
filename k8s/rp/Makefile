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
export MONGODB_URL								?= mongodb://mongoroot:secret@mongodb-demo:27017

OS 				= $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH  				= $(shell uname -m | sed 's/x86_64/amd64/')

#IMAGES
RP_IMG					?= ghcr.io/trustbloc-cicd/sandbox-rp:0.1.9-snapshot-bc094bb

# do not modify
KUSTOMIZE_DIR       	= kustomize/rp
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
deploy: prechecks kustomize kubectl set-images set-labels deploy-rp

.PHONY: prechecks
prechecks:
ifeq (, $(shell stat ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} 2>/dev/null))
	@echo "Environment not found ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}"
	@exit 1
endif

.PHONY: set-labels
set-labels: kustomize
	@pushd ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/rp &&\
		${KUSTOMIZE} edit set label ${COMMON_LABELS} &&\
		popd

.PHONY: set-images
set-images: kustomize
	@pushd ${KUSTOMIZE_DIR}/base &&\
	${KUSTOMIZE} edit set image sandbox-rp=${RP_IMG} &&\
	popd

.PHONY: deploy-rp
deploy-rp: prechecks kustomize kubectl
	@minikube image load $(RP_IMG)
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/rp | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: prechecks kustomize kubectl set-images set-labels undeploy-rp

.PHONY: undeploy-rp
undeploy-rp: prechecks kustomize kubectl
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/rp | $(KUBECTL) delete -f -

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
