# 
# Copyright SecureKey Technologies Inc. All Rights Reserved. 
# 
# SPDX-License-Identifier: Apache-2.0 
# 

#!/usr/bin/env bash
set -e

# Set default values, which may be overriden by the environment variables
: ${DOMAIN:=trustbloc.dev}
: ${MEMORY:=6g}
: ${CPUS:=4}
: ${ADDONS:=ingress,ingress-dns,dashboard}

OS=$( uname -s | tr '[:upper:]' '[:lower:]' )

# Use specified driver if set, otherwise minikube will auto-detect the best default driver for a given platform
if [[ -n $DRIVER ]]; then
    DRIVER="--driver=$DRIVER"
else
    # MacOS requires hyperkit driver instead of the auto-detected for compatibility with ingress addon
    if [[ $OS == darwin ]]; then
        DRIVER='--driver=hyperkit'
    fi
fi

minikube start --memory=$MEMORY --cpus=$CPUS --addons=$ADDONS $DRIVER $MINIKUBE_OPTIONS

source ./coredns_patch.sh

echo '!!! Make sure you have these entries added to your /etc/hosts !!!'
echo '=========================== CUT =========================='
generate_host_entries
echo '=========================== CUT =========================='
