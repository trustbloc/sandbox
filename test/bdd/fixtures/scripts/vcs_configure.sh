#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# issuer profiles
/tmp/scripts/vcs/issuer-trustbloc-profiles.sh
/tmp/scripts/vcs/issuer-interop-profiles.sh
/tmp/scripts/vcs/issuer-vendor-profiles.sh

# holder profiles
/tmp/scripts/vcs/holder-interop-profiles.sh
