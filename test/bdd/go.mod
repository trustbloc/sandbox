// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sandbox/test/bdd

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/cucumber/godog v0.8.1
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper v1.7.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	github.com/trustbloc/edge-service v0.1.7-0.20210310202014-13c73a748961
	github.com/trustbloc/fabric-peer-test-common v0.1.6
)

replace github.com/hyperledger/fabric-protos-go => github.com/trustbloc/fabric-protos-go-ext v0.1.5
