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

git clone -b chore-kms-common-aggrigate-1 https://github.com/alialkhalidi/k8s $core_dir
git checkout ${TRUSTBLOC_CORE_K8S_COMMIT}

# uncomment below line to link deployments to https://github.com/trustbloc/k8s directly (assuming k8s repo is in same folder as sandbox)
# rm -rf $core_dir && mkdir -p $core_dir && ln -s ../../../k8s/* $core_dir

cd $root

echo "pull trustbloc core deployment configs - end"
