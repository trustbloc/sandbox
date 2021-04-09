#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace golangci/golangci-lint:v1.31 golangci-lint run
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/issuer-rest golangci/golangci-lint:v1.31 golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/rp-rest golangci/golangci-lint:v1.31 golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/ace-rp-rest golangci/golangci-lint:v1.31 golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/login-consent-server golangci/golangci-lint:v1.31 golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/cmd golangci/golangci-lint:v1.31 golangci-lint run -c ../../.golangci.yml
