#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

/tmp/scripts/vcs/trustbloc-profiles.sh
/tmp/scripts/vcs/interop-profiles.sh
/tmp/scripts/vcs/vendor-profiles.sh
