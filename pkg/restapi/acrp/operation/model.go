/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "encoding/json"

type createVaultResp struct {
	ID string `json:"id"`
}

type saveDocReq struct {
	ID      string          `json:"id"`
	Content json.RawMessage `json:"content"`
	Tags    []string        `json:"tags"`
}

type userData struct {
	Password        string `json:"password"`
	VaultID         string `json:"vaultID"`
	NationalIDDocID string `json:"nationalIDDocID"`
}

type sessionData struct {
	State       string `json:"state"`
	CallbackURL string `json:"callbackURL"`
}

type clientReq struct {
	DID      string `json:"did"`
	Callback string `json:"callback"`
}

type clientResp struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	DID          string `json:"did"`
	Callback     string `json:"callback"`
}

type clientData struct {
	ClientID string `json:"clientID"`
	DID      string `json:"did"`
	Callback string `json:"callback"`
}

type profileData struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	DID          string `json:"did"`
	Callback     string `json:"callback"`
}
