/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
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
