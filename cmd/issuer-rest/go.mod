// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/issuer-rest

replace github.com/trustbloc/edge-sandbox => ../..

require (
	github.com/gorilla/mux v1.7.4
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.4
	github.com/trustbloc/edge-sandbox v0.0.0
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
)

go 1.13
