// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sandbox/cmd/ace-rp-rest

replace github.com/trustbloc/sandbox => ../..

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210331105523-60637a465684
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210331113925-b13dedfe75eb
	github.com/trustbloc/sandbox v0.0.0
)

go 1.15
