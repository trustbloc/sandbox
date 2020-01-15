/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	oauthCookieName = "oauthstate"
	stateFormKey    = "state"
	codeFormKey     = "code"

	defaultCookieExpiry = 20
	stateValueLength    = 16 // minutes
)

// Issuer implements token issuing
type Issuer struct {
	oauthConfig *oauth2.Config
}

// New creates new token issuer
func New(oauthConfig *oauth2.Config) *Issuer {
	return &Issuer{oauthConfig: oauthConfig}
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
func (i *Issuer) AuthCodeURL(w http.ResponseWriter) string {
	// AuthCodeURL receives state that is a token to protect the user from CSRF attacks
	oauthState := generateStateOauthCookie(w)

	return i.oauthConfig.AuthCodeURL(oauthState)
}

// Exchange will exchange auth code for auth token
func (i *Issuer) Exchange(r *http.Request) (*oauth2.Token, error) {
	// read oauthState from cookie
	oauthState, err := r.Cookie(oauthCookieName)
	if err != nil {
		return nil, err
	}

	// validate that oauth cookie state matches the the state query parameter on your redirect callback
	if r.FormValue(stateFormKey) != oauthState.Value {
		return nil, errors.New("invalid oauth state")
	}

	// exchange code for token
	token, err := i.oauthConfig.Exchange(context.Background(), r.FormValue(codeFormKey))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	// generate random bytes for state value
	b := make([]byte, stateValueLength)

	_, err := rand.Read(b)
	if err != nil {
		log.Error(err)
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: oauthCookieName,
		Value:   state,
		Expires: time.Now().Add(defaultCookieExpiry * time.Minute)}

	http.SetCookie(w, &cookie)

	return state
}
