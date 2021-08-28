// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sandbox/cmd/ace-rp-rest

replace github.com/trustbloc/sandbox => ../..

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210819214613-1554e98c6f85
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	github.com/trustbloc/sandbox v0.0.0
)

go 1.16
