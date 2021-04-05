#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


CONTAINER_CMD         	 	?= docker
USER_ID                          = $(shell id -u)
DOCKER_CMD_RUN_OPTS            ?= -u $(USER_ID)
CONTAINER_CMD_RUN_OPTS         ?= $(if $(findstring docker,$(CONTAINER_CMD)),$(DOCKER_CMD_RUN_OPTS),)

export DEPLOYMENT_ENV	?= local
# space delimited of Key:Value pairs
COMMON_LABELS		:= instance:${DEPLOYMENT_ENV}
export DOMAIN      		?= trustbloc.dev
export COUCHDB_URL								?= couchdb://cdbadmin:secret@couchdb:5984

OS 				= $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH  				= $(shell uname -m | sed 's/x86_64/amd64/')

#IMAGES
ACE_RP_IMG				?= ghcr.io/trustbloc-cicd/sandbox-ace-rp:0.1.7-snapshot-dc141e4
RP_IMG					?= ghcr.io/trustbloc-cicd/sandbox-rp:0.1.7-snapshot-dc141e4
ISSUER_IMG			?= ghcr.io/trustbloc-cicd/sandbox-issuer:0.1.7-snapshot-dc141e4
CLI_IMG				?= ghcr.io/trustbloc-cicd/sandbox-cli:0.1.7-snapshot-dc141e4
# do not modify
KUSTOMIZE_DIR       	= kustomize/demo-applications
CERTS_OUTPUT_DIR      	 	= ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/certs
REGISTRY_DIRECTORY           	= ${KUSTOMIZE_DIR}/base/registry
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

.PHONY: generate-test-certs
generate-test-certs: clean-certs
	@echo $(abspath .)
	@$(CONTAINER_CMD) run ${CONTAINER_CMD_RUN_OPTS} -i --rm \
		-v $(abspath .):/opt/workspace:Z \
		-e DOMAIN=${DOMAIN} \
		-e CERTS_OUTPUT_DIR=${CERTS_OUTPUT_DIR} \
		--entrypoint "/opt/workspace/scripts/generate_test_certs.sh" \
		docker.io/frapsoft/openssl:latest
	@cd ${CERTS_OUTPUT_DIR} && ln -fs trustbloc-dev-ca.crt ca.crt
	@cd ${CERTS_OUTPUT_DIR} && ln -fs ${DOMAIN}.key tls.key
	@cd ${CERTS_OUTPUT_DIR} && ln -fs ${DOMAIN}.crt tls.crt

.PHONY: deploy
deploy: prechecks kustomize set-images set-labels deploy-demo-applications

.PHONY: prechecks
prechecks:
ifeq (, $(shell stat ${REGISTRY_DIRECTORY}/.dockerconfigjson 2>/dev/null))
	@echo "docker registry config not found: ${REGISTRY_DIRECTORY}/.dockerconfigjson"
	@exit 1
else ifeq (, $(shell stat ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} 2>/dev/null))
	@echo "Environment not found ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}"
	@exit 1
endif

.PHONY: set-labels
set-labels: kustomize
	@pushd ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/demo-applications &&\
		${KUSTOMIZE} edit set label ${COMMON_LABELS} &&\
		popd

.PHONY: set-images
set-images: kustomize
	@pushd ${KUSTOMIZE_DIR}/base/rp &&\
	${KUSTOMIZE} edit set image sandbox-rp=${RP_IMG} &&\
	popd && \
	pushd ${KUSTOMIZE_DIR}/base/issuer &&\
	${KUSTOMIZE} edit set image sandbox-issuer=${ISSUER_IMG} &&\
	popd && \
	pushd ${KUSTOMIZE_DIR}/base/ace-rp &&\
	${KUSTOMIZE} edit set image sandbox-ace-rp=${ACE_RP_IMG} &&\
	popd &&\
	pushd ${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/demo-applications &&\
	${KUSTOMIZE} edit set image sandbox-cli=${CLI_IMG} &&\
	popd

.PHONY: deploy-demo-applications
deploy-demo-applications: prechecks kustomize
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/demo-applications | kubectl apply -f -

.PHONY: undeploy
undeploy: prechecks kustomize set-images set-labels undeploy-demo-applications

.PHONY: undeploy-demo-applications
undeploy-demo-applications: prechecks kustomize
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV}/demo-applications | kubectl delete -f -

.PHONY: kustomize
kustomize:
ifeq (, $(shell which kustomize 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p bin ;\
	curl -sSLo - https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v4.0.4/kustomize_v4.0.4_$(OS)_$(ARCH).tar.gz | tar xzf - -C bin/ ;\
	}
KUSTOMIZE=$(realpath ./bin/kustomize)
else
KUSTOMIZE=$(shell which kustomize)
endif

.PHONY: clean
clean: clean-all

.PHONY: clean-all
clean-all: clean-certs clean-registry

.PHONY: clean-no-registry
clean-no-registry: clean-certs

.PHONY: clean-certs
clean-certs:
	@rm -Rf ${CERTS_OUTPUT_DIR}

.PHONY: clean-registry
clean-registry:
	@rm -Rf ${REGISTRY_DIRECTORY}
