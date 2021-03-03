/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/hyperledger/aries-framework-go/pkg/doc/util"

type userData struct {
	ID              string `json:"id"`
	UserName        string `json:"userName"`
	VaultID         string `json:"vaultID"`
	NationalIDDocID string `json:"nationalIDDocID"`
}

type sessionData struct {
	DID         string `json:"did"`
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
	URL          string `json:"url"`
	DID          string `json:"did"`
	Callback     string `json:"callback"`
}

type userAuthData struct {
	Source        string                         `json:"source"`
	SubmittedTime *util.TimeWithTrailingZeroMsec `json:"submittedTime"`
	UserAuths     []userAuthorization            `json:"userAuths"`
}

type userAuthorization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AuthToken string `json:"authToken"`
}

type getUserDataResp struct {
	Users []userData `json:"users"`
}

type generateUserAuthReq struct {
	Users []string `json:"users"`
}

type extractResp struct {
	ExtractData []extractData `json:"extractData"`
}

type extractData struct {
	Source        string                         `json:"source"`
	SubmittedTime *util.TimeWithTrailingZeroMsec `json:"submittedTime"`
	Data          []userExtractedData            `json:"userDetails"`
}

type userExtractedData struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	NationalID string `json:"nationalID"`
}
