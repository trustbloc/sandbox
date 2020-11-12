// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox

go 1.15

require (
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201110161050-249e1c428734
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201026212420-22cb30832cd8
	github.com/trustbloc/edge-service v0.1.5-0.20201111202603-13d782734e52
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
