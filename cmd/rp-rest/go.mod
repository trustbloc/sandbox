// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/rp-rest

replace github.com/trustbloc/edge-sandbox => ../..

require (
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.4-0.20200814194611-5f3b95f18b63
	github.com/trustbloc/edge-sandbox v0.0.0
)

go 1.13
