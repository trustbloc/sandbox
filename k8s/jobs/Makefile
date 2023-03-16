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
export DOMAIN      		?= local.trustbloc.dev
export BLOC_DOMAIN      		?= orb-1.local.trustbloc.dev
# space delimited of Key:Value pairs
COMMON_LABELS		:= instance:${DEPLOYMENT_ENV}

OS 				= $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH  				= $(shell uname -m | sed 's/x86_64/amd64/')

#IMAGES
CLI_IMG				?= ghcr.io/trustbloc-cicd/sandbox-cli:0.1.9-snapshot-bc094bb

# do not modify
KUSTOMIZE_DIR       	= kustomize/jobs
PREFIX							?=
KUSTOMIZE_BUILD_OPTS			?= --load-restrictor LoadRestrictionsNone --enable-alpha-plugins
export KUSTOMIZE_PLUGIN_HOME						= $(abspath .)/kustomize/plugin

.PHONY: setup-no-certs
setup-no-certs:
	@echo setup-no-certs


.PHONY: all
all: deploy

.PHONY: deploy
deploy: prechecks kustomize kubectl set-images set-labels deploy-jobs

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
	@pushd ${KUSTOMIZE_DIR}/overlays/common &&\
		${KUSTOMIZE} edit set image sandbox-cli=${CLI_IMG} &&\
		popd

.PHONY: delete-jobs
delete-jobs:
	@echo deleting jobs
	$(KUBECTL) -n default delete job \
	ace-rp-profiles \
	adapter-issuer-add-profiles \
	holder-vcs-add-profiles \
	auth-hydra-create-client \
	hydra-create-client \
	issuer-register-tenant \
	issuer-vcs-add-profiles \
	orb-add-followers \
	process-oathkeeper-template \
	rp-register-tenant \
#	user-data \
	verifier-vcs-add-profiles \
	--ignore-not-found=true

.PHONY: deploy-jobs
deploy-jobs: prechecks kustomize kubectl
	$(KUSTOMIZE) build ${KUSTOMIZE_BUILD_OPTS} \
	${KUSTOMIZE_DIR}/overlays/${DEPLOYMENT_ENV} | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: prechecks kustomize kubectl set-images set-labels undeploy-jobs

.PHONY: undeploy-jobs
undeploy-jobs: prechecks kustomize kubectl
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
