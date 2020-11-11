// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-sandbox/cmd/rp-rest

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/trustbloc/edge-sandbox => ../..
)

require (
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/spf13/cobra v0.0.7
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201026212420-22cb30832cd8
	github.com/trustbloc/edge-sandbox v0.0.0
)

go 1.15
