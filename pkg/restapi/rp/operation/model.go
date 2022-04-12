/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
)

type verifyPresentationRequest struct {
	Checks    []string        `json:"checks"`
	Domain    string          `json:"domain"`
	Challenge string          `json:"challenge"`
	VP        json.RawMessage `json:"vp"`
}

type verifyCredentialRequest struct {
	Checks []string        `json:"checks"`
	VC     json.RawMessage `json:"vc"`
}

type oidcVpRequest struct {
	WalletAuthURL          string          `json:"walletAuthURL"`
	PresentationDefinition json.RawMessage `json:"pEx"`
}

type oidcAuthClaims struct {
	VPToken *vpToken `json:"vp_token"`
}

type vpToken struct {
	PresDef *presexch.PresentationDefinition `json:"presentation_definition"`
}

type oidcTokenClaims struct {
	VPToken *vpTokenClaim `json:"_vp_token"`
}

type vpTokenClaim struct {
	PresSub *presexch.PresentationSubmission `json:"presentation_submission"`
}
