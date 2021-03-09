/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
)

type verifyDIDAuthReq struct {
	Holder      string          `json:"holder"`
	Domain      string          `json:"domain"`
	Challenge   string          `json:"challenge"`
	DIDAuthResp json.RawMessage `json:"didAuthResp"`
}

type createCredentialReq struct {
	Scope      string `json:"scope"`
	VCSProfile string `json:"vcsProfile"`
	UserID     string `json:"userID"`
}
