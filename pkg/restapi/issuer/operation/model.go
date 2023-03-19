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
	Holder            string                 `json:"holder"`
	VCSProfile        string                 `json:"vcsProfile"`
	Scope             string                 `json:"scope"`
	Collection        string                 `json:"collection"`
	UserID            string                 `json:"userID"`
	CustomSubjectData map[string]interface{} `json:"customSubjectData"`
}

type txnData struct {
	UserID string `json:"userID"`
	Scope  string `json:"scope"`
	Token  string `json:"token"`
}

type searchData struct {
	Scope    string                 `json:"scope"`
	UserData map[string]interface{} `json:"userData"`
}

type generateCredentialReq struct {
	ID         string `json:"id"`
	Holder     string `json:"holder"`
	VCSProfile string `json:"vcsProfile"`
}

type oidcIssuanceRequest struct {
	WalletInitIssuanceURL string          `json:"walletInitIssuanceURL"`
	CredentialTypes       string          `json:"credentialTypes"`
	ManifestIDs           string          `json:"manifestIDs"`
	IssuerURL             string          `json:"issuerURL"`
	CredManifest          json.RawMessage `json:"credManifest"`
	Credential            json.RawMessage `json:"credToIssue"`
}

type issuerConfiguration struct {
	Issuer                string          `json:"issuer"`
	AuthorizationEndpoint string          `json:"authorization_endpoint"`
	CredentialEndpoint    string          `json:"credential_endpoint"`
	TokenEndpoint         string          `json:"token_endpoint"`
	CredentialManifests   json.RawMessage `json:"credential_manifests"`
}

type initiateOIDC4CIResponse struct {
	OfferCredentialURL string  `json:"offer_credential_URL"`
	TxID               string  `json:"tx_id"`
	UserPin            *string `json:"user_pin"`
}

type initiateOIDC4CIRequest struct {
	ClaimData                 *map[string]interface{} `json:"claim_data,omitempty"`
	ClaimEndpoint             string                  `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceURL string                  `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string                  `json:"client_wellknown,omitempty"`
	CredentialTemplateID      string                  `json:"credential_template_id,omitempty"`
	GrantType                 string                  `json:"grant_type,omitempty"`
	OpState                   string                  `json:"op_state,omitempty"`
	ResponseType              string                  `json:"response_type,omitempty"`
	Scope                     []string                `json:"scope,omitempty"`
	UserPinRequired           bool                    `json:"user_pin_required,omitempty"`
}

// Profile represents issuer profile in demo app.
type Profile struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	CredentialTemplateID string                 `json:"credential_template_id"`
	Claims               map[string]interface{} `json:"claims"`
}

type profileView struct {
	ID         string
	Name       string
	IsSelected bool
}
