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


golangci_image="golangci/golangci-lint:v1.42.1"

# these are useful for adjusting the linter's root directory, to allow linting while using local replaces
root_dir=$(pwd)
# root_dir=$(pwd)/../../
internal_root_dir="."
# internal_root_dir="trustbloc/edge-sandbox"

shopt -s globstar
for i in **/*.mod; do
  mod_dir=$(dirname ${i})

  echo "linting ${mod_dir}"

  ${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v ${root_dir}:/opt/workspace -w /opt/workspace/${internal_root_dir}/${mod_dir} ${golangci_image} golangci-lint run -c /opt/workspace/${internal_root_dir}/.golangci.yml --path-prefix "${mod_dir}"
done

# this isn't covered by the loop, as there's no go.mod file in test/cmd
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/cmd ${golangci_image} golangci-lint run -c ../../.golangci.yml
