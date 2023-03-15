# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: all
all: clean bdd-test

.PHONY: bdd-test
bdd-test:
	@make bdd-test -C ./ace
	@make bdd-test -C ./issuer

.PHONY: clean
clean:
	@make clean -C ./ace
	@make clean -C ./issuer
