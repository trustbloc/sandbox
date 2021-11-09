#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

# Set default values, which may be overriden by the environment variables
: ${DOMAIN:=trustbloc.dev}

source ./coredns_patch.sh

echo 'updating entries in /etc/hosts'
echo '=========================== CUT =========================='
generate_host_entries | sudo tee -a /etc/hosts
echo '=========================== CUT =========================='
