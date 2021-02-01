// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/issuer-rest

replace github.com/trustbloc/edge-sandbox => ../..

require (
	github.com/gorilla/mux v1.8.0
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/edge-sandbox v0.0.0
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
)

go 1.15
