// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/rp-rest

replace github.com/trustbloc/edge-sandbox => ../..

require (
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/edge-sandbox v0.0.0
)

go 1.15
