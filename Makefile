# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
ISSUER_REST_PATH=cmd/issuer-rest
RP_REST_PATH=cmd/rp-rest
STRAPI_DEMO_PATH=cmd/strapi-demo

DOCKER_OUTPUT_NS         ?= docker.pkg.github.com
# Namespace for the issuer image
ISSUER_REST_IMAGE_NAME   ?= trustbloc/edge-sandbox/issuer-rest
# Namespace for the ro image
RP_REST_IMAGE_NAME   ?= trustbloc/edge-sandbox/rp-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER     ?= 1.13.1

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
demo-start: clean issuer-rest-docker rp-rest-docker generate-test-keys
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

.PHONY: hydra-test-app
hydra-test-app:
	@scripts/hydra_test_app.sh

.PHONY: issuer-rest
issuer-rest:
	@echo "Building issuer-rest"
	@mkdir -p ./build/bin/issuer
	@cp -r ${ISSUER_REST_PATH}/static ./build/bin/issuer
	@cd ${ISSUER_REST_PATH} && go build -o ../../build/bin/issuer/issuer-rest main.go

.PHONY: rp-rest
rp-rest:
	@echo "Building rp-rest"
	@mkdir -p ./build/bin/rp
	@cp -r ${RP_REST_PATH}/static ./build/bin/rp
	@cd ${RP_REST_PATH} && go build -o ../../build/bin/rp/rp-rest main.go

.PHONY: strapi-build
strapi-build:
	@echo "Building strapi demo"
	@mkdir -p ./build/bin
	@cd ${STRAPI_DEMO_PATH} && go build -o ../../build/bin/strapi-demo main.go

.PHONY: strapi-setup
demo-setup: strapi-build
	@scripts/demo-setup.sh


.PHONY: issuer-rest-docker
issuer-rest-docker:
	@echo "Building issuer rest docker image"
	@docker build -f ./images/issuer-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ISSUER_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: rp-rest-docker
rp-rest-docker:
	@echo "Building rp rest docker image"
	@docker build -f ./images/rp-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(RP_REST_IMAGE_NAME):latest \
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

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./build
	@rm -Rf ./test/bdd/fixtures/keys
	@rm -Rf ./test/bdd/fixtures/oathkeeper/rules/resource-server.json