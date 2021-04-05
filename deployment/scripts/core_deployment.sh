#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "pull trustbloc core deployment configs - start"

root=$(pwd)
core_dir=$root/.core

rm -rf $core_dir
mkdir -p $core_dir
cd $core_dir

git clone -b main https://github.com/trustbloc/deployment $core_dir
git checkout ${TRUSTBLOC_CORE_DEPLOYMENT_COMMIT}

cd $root

echo "pull trustbloc core deployment configs - end"
