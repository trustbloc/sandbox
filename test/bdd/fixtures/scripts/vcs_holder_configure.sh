#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# holder profiles
/tmp/scripts/vcs/holder-trustbloc-profiles.sh
/tmp/scripts/vcs/holder-vendor-profiles.sh
