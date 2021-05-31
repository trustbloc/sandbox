// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sandbox/cmd/rp-rest

replace github.com/trustbloc/sandbox => ../..

require (
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210527163745-994ae929f957
	github.com/trustbloc/sandbox v0.0.0
)

go 1.16
