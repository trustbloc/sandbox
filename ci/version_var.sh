#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.5
IS_RELEASE=true

SOURCE_REPO=edge-sandbox
BASE_RP_PKG_NAME=rp-rest
BASE_ISSUER_PKG_NAME=issuer-rest
BASE_LOGIN_PKG_NAME=login-consent-server
RELEASE_REPO=docker.pkg.github.com/trustbloc/${SOURCE_REPO}
SNAPSHOT_REPO=docker.pkg.github.com/trustbloc-cicd/snapshot

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
fi

export EDGE_SANDBOX_TAG=$PROJECT_VERSION
export RP_REST_PKG=${PROJECT_PKG_REPO}/${BASE_RP_PKG_NAME}
export ISSUER_REST_PKG=${PROJECT_PKG_REPO}/${BASE_ISSUER_PKG_NAME}
export LOGIN_PKG=${PROJECT_PKG_REPO}/${BASE_LOGIN_PKG_NAME}
