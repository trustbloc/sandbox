# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD          ?= go
ARCH             = $(shell go env GOARCH)
ISSUER_REST_PATH = cmd/issuer-rest
RP_REST_PATH     = cmd/rp-rest
ACE_RP_REST_PATH   = cmd/ace-rp-rest
LOGIN_CONSENT_PATH = cmd/login-consent-server
DEMO_CMS_PATH 		= test/cmd/cms
DEMO_CLI_PATH       = test/cmd/demo

DOCKER_OUTPUT_NS         ?= ghcr.io
# Namespace for the issuer image
ISSUER_REST_IMAGE_NAME   ?= trustbloc/sandbox-issuer
# Namespace for the rp image
RP_REST_IMAGE_NAME       ?= trustbloc/sandbox-rp
# Namespace for the ace-rp image
ACE_RP_REST_IMAGE_NAME       ?= trustbloc/sandbox-ace-rp
# Namespace for the login consent server image
LOGIN_CONSENT_SEVER_IMAGE_NAME   ?= trustbloc/sandbox-login-consent-server
# Namespace for the cm rest image
DEMO_CMS_IMAGE_NAME   ?= trustbloc/sandbox-cms
# ELEMENT API SIDETREE REQUEST URL
DID_ELEMENT_SIDETREE_REQUEST_URL ?= https://element-did.com/api/v1/sidetree/requests
# Namespace for the sandbox cli image
SANDBOX_CLI_IMAGE_NAME       ?= trustbloc/sandbox-cli

# TrustBloc core k8s deployment scripts https://github.com/trustbloc/k8s
TRUSTBLOC_CORE_K8S_COMMIT=24eee5223b0bba819a22d3e56e511039b4bec777

# Tool commands (overridable)
ALPINE_VER ?= 3.16
GO_VER     ?= 1.19

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: sandbox-cli-docker
sandbox-cli-docker:
	@echo "Building sandbox-cli docker image"
	@docker build -f ./images/sandbox-cli/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(SANDBOX_CLI_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: demo-cli
demo-cli:
	@echo "Building demo-cli"
	@mkdir -p ./.build/bin
	@cd ${DEMO_CLI_PATH} && go build -o ../../../.build/bin/demo main.go

.PHONY: issuer-rest
issuer-rest:
	@echo "Building issuer-rest"
	@mkdir -p ./.build/bin/issuer
	@cp -r ${ISSUER_REST_PATH}/static ./.build/bin/issuer
	@cd ${ISSUER_REST_PATH} && go build -o ../../.build/bin/issuer/issuer-rest main.go

.PHONY: rp-rest
rp-rest:
	@echo "Building rp-rest"
	@mkdir -p ./.build/bin/rp
	@cp -r ${RP_REST_PATH}/static ./.build/bin/rp
	@cd ${RP_REST_PATH} && go build -o ../../.build/bin/rp/rp-rest main.go

.PHONY: ace-rp-rest
ace-rp-rest:
	@echo "Building ace-rp-rest"
	@mkdir -p ./.build/bin/ace-rp
	@cp -r ${ACE_RP_REST_PATH}/static ./.build/bin/ace-rp
	@cd ${ACE_RP_REST_PATH} && go build -o ../../.build/bin/ace-rp/ace-rp-rest main.go

.PHONY: login-consent-server
login-consent-server:
	@echo "Building login-consent-server"
	@mkdir -p ./.build/bin/login-consent
	@cp -r ${LOGIN_CONSENT_PATH}/templates ./.build/bin/login-consent
	@cd ${LOGIN_CONSENT_PATH} && go build -o ../../.build/bin/login-consent/server main.go

.PHONY: sandbox-cms
sandbox-cms:
	@echo "Building sandbox-cms"
	@mkdir -p ./.build/bin/cms
	@cp -r ${DEMO_CMS_PATH}/testdata ./.build/bin/cms
	@cd ${DEMO_CMS_PATH} && go build -o ../../../.build/bin/cms/cms main.go

.PHONY: sandbox-issuer-docker
sandbox-issuer-docker:
	@echo "Building issuer rest docker image"
	@docker build -f ./images/issuer-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ISSUER_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: sandbox-rp-docker
sandbox-rp-docker:
	@echo "Building rp rest docker image"
	@docker build -f ./images/rp-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(RP_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: sandbox-ace-rp-docker
sandbox-ace-rp-docker:
	@echo "Building ace-rp rest docker image"
	@docker build -f ./images/ace-rp-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ACE_RP_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: login-consent-server-docker
login-consent-server-docker:
	@echo "Building login consent server docker image"
	@docker build -f ./images/login-consent-server/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(LOGIN_CONSENT_SEVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: sandbox-cms-docker
sandbox-cms-docker:
	@echo "Building sandbox-cms docker image"
	@docker build -f ./images/sandbox-cms/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(DEMO_CMS_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

create-element-did: clean
	@mkdir -p .build
	@cp scripts/create-element-did.js .build/
	@REQUEST_URL=$(DID_ELEMENT_SIDETREE_REQUEST_URL) scripts/create_element_did.sh

.PHONY: clean
clean: clean-build
	@make clean -C ./k8s

.PHONY: build-setup-deploy
build-setup-deploy: clean sandbox-issuer-docker sandbox-rp-docker sandbox-ace-rp-docker sandbox-cli-docker sandbox-cms-docker login-consent-server-docker
	@TRUSTBLOC_CORE_K8S_COMMIT=$(TRUSTBLOC_CORE_K8S_COMMIT) \
		make local-setup-deploy -C ./k8s

.PHONY: setup-deploy
setup-deploy: clean
	@TRUSTBLOC_CORE_K8S_COMMIT=$(TRUSTBLOC_CORE_K8S_COMMIT) make setup-deploy -C ./k8s

.PHONY: ci-setup-deploy
ci-setup-deploy: clean
	@TRUSTBLOC_CORE_K8S_COMMIT=$(TRUSTBLOC_CORE_K8S_COMMIT) make ci-setup-deploy -C ./k8s

.PHONY: undeploy-all
undeploy-all:
	@make undeploy-all -C ./k8s

.PHONY: deploy-all
deploy-all:
	@make deploy-all -C ./k8s

.PHONY: pull-core-deployment
pull-core-deployment:
	@make pull-core-deployment -C ./k8s

.PHONY: deploy-components
deploy-components:
       @COMPONENTS="$(COMPONENTS)" make deploy-components -C ./k8s

.PHONY: minikube-down
minikube-down:
	@make minikube-down -C ./k8s

.PHONY: automation-test-vcwallet
automation-test-vcwallet:
	@cd ./test/ui-automation && npm run test:vcwallet && npm run report

.PHONY: automation-test-local
automation-test-local:
	@cd ./test/ui-automation && npm run test:local && npm run report

.PHONY: automation-test-dev
automation-test-dev:
	@cd ./test/ui-automation && npm run test:dev && npm run report

.PHONY: automation-test
automation-test:
	@cd ./test/ui-automation && npm run test && npm run report

.PHONY: bdd-test
bdd-test:
	@make all  -C ./test/bdd

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./coverage.out
