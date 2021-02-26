#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
touch "$pwd"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.out
     rm profile.out
fi
}

# Running sandbox unit tests
PKGS=`go list github.com/trustbloc/sandbox/... 2> /dev/null | \
                                                  grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running issuer-rest unit tests
cd cmd/issuer-rest
PKGS=`go list github.com/trustbloc/sandbox/cmd/issuer-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit

# Running rp-rest unit tests
cd cmd/rp-rest
PKGS=`go list github.com/trustbloc/sandbox/cmd/rp-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit

# Running ace-rp-rest unit tests
cd cmd/ace-rp-rest
PKGS=`go list github.com/trustbloc/sandbox/cmd/ace-rp-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit

# Running login-consent unit tests
cd cmd/login-consent-server
PKGS=`go list github.com/trustbloc/sandbox/cmd/login-consent-server/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit
