# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD          ?= go
ARCH             = $(shell go env GOARCH)
ISSUER_REST_PATH = cmd/issuer-rest
RP_REST_PATH     = cmd/rp-rest
ACRP_REST_PATH   = cmd/acrp-rest
STRAPI_DEMO_PATH = cmd/strapi-demo
LOGIN_CONSENT_PATH = cmd/login-consent-server

DOCKER_OUTPUT_NS         ?= ghcr.io
# Namespace for the issuer image
ISSUER_REST_IMAGE_NAME   ?= trustbloc/sandbox-issuer
# Namespace for the rp image
RP_REST_IMAGE_NAME       ?= trustbloc/sandbox-rp
# Namespace for the acrp image
ACRP_REST_IMAGE_NAME       ?= trustbloc/sandbox-acrp
# Namespace for the login consent server image
LOGIN_CONSENT_SEVER_IMAGE_NAME   ?= trustbloc/sandbox-login-consent-server
# ELEMENT API SIDETREE REQUEST URL
DID_ELEMENT_SIDETREE_REQUEST_URL ?= https://element-did.com/api/v1/sidetree/requests

# Tool commands (overridable)
ALPINE_VER ?= 3.12
GO_VER     ?= 1.15

# Fabric tools docker image (overridable)
FABRIC_TOOLS_IMAGE   ?= hyperledger/fabric-tools
FABRIC_TOOLS_VERSION ?= 2.0.0-alpha
FABRIC_TOOLS_TAG     ?= $(ARCH)-$(FABRIC_TOOLS_VERSION)

# This can be a commit hash or a tag (or any git ref)
export FABRIC_CLI_EXT_VERSION ?= 015b6624fdc5d31895f2df09359f32f5bb78ad3e
export TRUSTBLOC_DID_METHOD ?= ebba2a4c7be02e4e97c2f3d2476b8d579d52bb99

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

.PHONY: demo-start
demo-start: clean did-method-cli sandbox-issuer-docker sandbox-rp-docker login-consent-server-docker sandbox-acrp-docker trustbloc-local-setup
	@scripts/sandbox_start.sh

.PHONY: demo-start-with-sidetree-fabric
demo-start-with-sidetree-fabric: export START_SIDETREE_FABRIC=true
demo-start-with-sidetree-fabric: clean did-method-cli sandbox-issuer-docker sandbox-rp-docker login-consent-server-docker sandbox-acrp-docker trustbloc-local-setup populate-fixtures fabric-cli
	@scripts/sandbox_start.sh

.PHONY: demo-stop
demo-stop:
	@scripts/sandbox_stop.sh

# trustbloc-local targets enable the sandbox hosts to be accessed by friendly names.
# trustbloc-local-setup: Creates a TLS CA into ~/.trustbloc-local/sandbox/trustbloc-dev-ca.crt
#                        Creates hosts entries into ~/.trustbloc-local/sandbox/hosts.
#                        These fixtures can be manually imported into the cert chain and /etc/hosts.
.PHONY: trustbloc-local-setup
trustbloc-local-setup: trustbloc-local-remove generate-test-keys
	@scripts/trustbloc_local_setup.sh

.PHONY: trustbloc-local-remove
trustbloc-local-remove:
	rm -Rf ~/.trustbloc-local/

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

.PHONY: acrp-rest
acrp-rest:
	@echo "Building acrp-rest"
	@mkdir -p ./.build/bin/acrp
	@cp -r ${ACRP_REST_PATH}/static ./.build/bin/acrp
	@cd ${ACRP_REST_PATH} && go build -o ../../.build/bin/acrp/acrp-rest main.go

.PHONY: login-consent-server
login-consent-server:
	@echo "Building login-consent-server"
	@mkdir -p ./.build/bin/login-consent
	@cp -r ${LOGIN_CONSENT_PATH}/templates ./.build/bin/login-consent
	@cd ${LOGIN_CONSENT_PATH} && go build -o ../../.build/bin/login-consent/server main.go

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

.PHONY: sandbox-acrp-docker
sandbox-acrp-docker:
	@echo "Building acrp rest docker image"
	@docker build -f ./images/acrp-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ACRP_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: login-consent-server-docker
login-consent-server-docker:
	@echo "Building login consent server docker image"
	@docker build -f ./images/login-consent-server/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(LOGIN_CONSENT_SEVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p test/bdd/fixtures/keys/tls
	@cp ~/.trustbloc-local/sandbox/certs/trustbloc-dev-ca.* test/bdd/fixtures/keys/tls 2>/dev/null || :
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edge-sandbox \
		--entrypoint "/opt/workspace/edge-sandbox/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: crypto-gen
crypto-gen:
	@echo "Generating crypto directory ..."
	@docker run -i \
		-v /$(abspath .):/opt/workspace/edge-sandbox -u $(shell id -u):$(shell id -g) \
		$(FABRIC_TOOLS_IMAGE):$(FABRIC_TOOLS_TAG) \
		//bin/bash -c "FABRIC_VERSION_DIR=fabric /opt/workspace/edge-sandbox/scripts/generate_crypto.sh"

.PHONY: channel-config-gen
channel-config-gen:
	@echo "Generating test channel configuration transactions and blocks ..."
	@docker run -i \
		-v /$(abspath .):/opt/workspace/edge-sandbox -u $(shell id -u):$(shell id -g) \
		$(FABRIC_TOOLS_IMAGE):$(FABRIC_TOOLS_TAG) \
		//bin/bash -c "FABRIC_VERSION_DIR=fabric/ /opt/workspace/edge-sandbox/scripts/generate_channeltx.sh"

.PHONY: populate-fixtures
populate-fixtures: clean
	@scripts/populate-fixtures.sh -f

fabric-cli:
	@scripts/build_fabric_cli.sh

create-element-did: clean
	@mkdir -p .build
	@cp scripts/create-element-did.js .build/
	@REQUEST_URL=$(DID_ELEMENT_SIDETREE_REQUEST_URL) scripts/create_element_did.sh

.PHONY: did-method-cli
did-method-cli: clean
	@scripts/build-did-method-cli.sh

.PHONY: generate-config-hash
generate-config-hash: did-method-cli
	@echo "Generate config hash"
	@scripts/generate_config_hash.sh

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./coverage.out
	@rm -Rf ./test/bdd/fixtures/oathkeeper/rules/resource-server.json
	@rm -Rf ./test/bdd/fixtures/fabric/channel
	@rm -Rf ./test/bdd/fixtures/fabric/crypto-config
	@rm -Rf ./test/bdd/fixtures/discovery-config/genesis-configs/*
	@rm -Rf ./test/bdd/fixtures/discovery-config/sidetree-mock/config
	@rm -Rf ./test/bdd/fixtures/discovery-config/sidetree-mock/temp
	@rm -Rf ./test/bdd/fixtures/discovery-config/sidetree-fabric/config
	@rm -Rf ./test/bdd/fixtures/discovery-config/sidetree-fabric/config-data-generated
