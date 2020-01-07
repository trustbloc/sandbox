# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
ISSUER_REST_PATH=cmd/issuer-rest

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

unit-test:
	@scripts/check_unit.sh

hydra-start:
	@scripts/hydra_start.sh

hydra-configure:
	@scripts/hydra_configure.sh

hydra-stop:
	@scripts/hydra_stop.sh

hydra-test-app:
	@scripts/hydra_test_app.sh

issuer-rest:
	@echo "Building issuer-rest"
	@mkdir -p ./build/bin
	@cd ${ISSUER_REST_PATH} && go build -o ../../build/bin/issuer-rest main.go
