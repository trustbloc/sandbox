#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.8
IS_RELEASE=false

BASE_RP_PKG_NAME=sandbox-rp
BASE_ACE_RP_PKG_NAME=sandbox-ace-rp
BASE_ISSUER_PKG_NAME=sandbox-issuer
BASE_LOGIN_PKG_NAME=sandbox-login-consent-server
BASE_CMS_PKG_NAME=sandbox-cms
BASE_CLI_NAME=sandbox-cli
RELEASE_REPO=ghcr.io/trustbloc
SNAPSHOT_REPO=ghcr.io/trustbloc-cicd

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
export ACE_RP_REST_PKG=${PROJECT_PKG_REPO}/${BASE_ACE_RP_PKG_NAME}
export ISSUER_REST_PKG=${PROJECT_PKG_REPO}/${BASE_ISSUER_PKG_NAME}
export LOGIN_PKG=${PROJECT_PKG_REPO}/${BASE_LOGIN_PKG_NAME}
export CMS_PKG=${PROJECT_PKG_REPO}/${BASE_CMS_PKG_NAME}
export CLI_PKG=${PROJECT_PKG_REPO}/${BASE_CLI_NAME}
