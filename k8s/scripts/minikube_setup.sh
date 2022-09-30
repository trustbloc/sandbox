#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

# Set default values, which may be overriden by the environment variables
: ${DOMAIN:=trustbloc.dev}
: ${MEMORY:=6g}
: ${CPUS:=4}
: ${ADDONS:=ingress,ingress-dns,dashboard}
: ${KUBERNETES_VERSION:=v1.21.2}

OS=$( uname -s | tr '[:upper:]' '[:lower:]' )

# If necessary, convert the reported architecture name to an (equivalent) name that we check for in this script.
ARCH=$( uname -m)
case $ARCH in
   x86_64)
     ARCH="amd64"
     ;;
   aarch64)
     ARCH="arm64"
     ;;
esac

# Use specified driver if set, otherwise minikube will auto-detect the best default driver for a given platform
if [[ -n $DRIVER ]]; then
    DRIVER="--driver=$DRIVER"
else
    if [[ $OS == darwin ]]; then
      # When using MacOS on an amd64 system, we need to use the hyperkit driver for compatibility with the ingress
      # add-on.
      if [[ $ARCH == amd64 ]]; then
          DRIVER='--driver=hyperkit'
      fi

      # Hyperkit isn't supported on arm-based MacOS, so as a workaround we use Docker and a background service to enable
      # host<->VM communication (described in more detail in the README). Here we also print out a message
      # alerting/reminding the user about the background service.
      if [[ $ARCH == arm64 ]]; then
          echo '!!! Make sure the docker-mac-net-connect brew service is running. See https://github.com/trustbloc/k8s/blob/main/README.md for more information. !!!'
          DRIVER='--driver=docker'
      fi
    fi
fi

minikube start --memory=$MEMORY --cpus=$CPUS --addons=$ADDONS --kubernetes-version=$KUBERNETES_VERSION $DRIVER $MINIKUBE_OPTIONS

source ./coredns_patch.sh

echo '!!! Make sure you have these entries added to your /etc/hosts !!!'
echo '=========================== CUT =========================='
generate_host_entries
echo '=========================== CUT =========================='
