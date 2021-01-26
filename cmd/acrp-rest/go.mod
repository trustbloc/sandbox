// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/acrp-rest

replace (
	github.com/trustbloc/edge-core => github.com/trustbloc/edge-core v0.1.5-0.20201126210935-53388acb41fc
	github.com/trustbloc/edge-sandbox => ../..
)

require (
	github.com/cenkalti/backoff/v4 v4.1.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
	github.com/trustbloc/edge-sandbox v0.0.0
	golang.org/x/net v0.0.0-20201009032441-dbdefad45b89 // indirect
)

go 1.15
