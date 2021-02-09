/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"
	"golang.org/x/oauth2"
)

const (
	oauthCookieName = "oauthstate"
	stateFormKey    = "state"
	codeFormKey     = "code"

	defaultCookieExpiry = 20
	stateValueLength    = 16 // minutes
)

var logger = log.New("sandbox-token-issuer")

// Option configures the issuer
type Option func(opts *Issuer)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Issuer) {
		opts.tlsConfig = tlsConfig
	}
}

// Issuer implements token issuing
type Issuer struct {
	oauthConfig *oauth2.Config
	tlsConfig   *tls.Config
}

// New creates new token issuer
func New(oauthConfig *oauth2.Config, opts ...Option) *Issuer {
	issuer := &Issuer{oauthConfig: oauthConfig}

	for _, opt := range opts {
		opt(issuer)
	}

	return issuer
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
	token, err := i.oauthConfig.Exchange(i.createContext(), r.FormValue(codeFormKey))
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Client returns an HTTP client using the provided token.
func (i *Issuer) Client(t *oauth2.Token) *http.Client {
	ctx := i.createContext()
	return oauth2.NewClient(ctx, i.oauthConfig.TokenSource(ctx, t))
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	// generate random bytes for state value
	b := make([]byte, stateValueLength)

	_, err := rand.Read(b)
	if err != nil {
		logger.Errorf(err.Error())
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: oauthCookieName,
		Value:   state,
		Expires: time.Now().Add(defaultCookieExpiry * time.Minute)}

	http.SetCookie(w, &cookie)

	return state
}

func (i *Issuer) createContext() context.Context {
	ctx := context.Background()
	tr := &http.Transport{
		TLSClientConfig: i.tlsConfig,
	}
	httpClient := &http.Client{Transport: tr}

	return context.WithValue(ctx, oauth2.HTTPClient, httpClient)
}
