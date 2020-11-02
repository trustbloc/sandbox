/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestCreateOIDCRequest(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		config, cleanup := config()
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		result, err := svc.CreateOIDCRequest("1", scope)
		require.NoError(t, err)
		u, err := url.Parse(result)
		require.NoError(t, err)
		scopes := strings.Split(u.Query().Get("scope"), " ")
		require.Contains(t, scopes, oidc.ScopeOpenID)
		require.Contains(t, scopes, scope)
		require.NotEmpty(t, u.Query().Get("state"))
		require.Equal(t, config.OIDCClientID, u.Query().Get("client_id"))
		require.Equal(t,
			fmt.Sprintf("%s%s", config.OIDCCallbackURL, oauth2CallbackPath), u.Query().Get("redirect_uri"))
	})
}

func TestHandleOIDCCallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		code := uuid.New().String()

		config, configCleanup := config()
		defer configCleanup()

		o, err := New(config)
		require.NoError(t, err)

		o.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{
				oauth2Claim: uuid.New().String(),
			}}
		}

		o.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{
				verifyVal: &mockToken{oidcClaimsFunc: func(v interface{}) error {
					m, ok := v.(*map[string]interface{})
					if !ok {
						return fmt.Errorf("not map")
					}
					(*m)["k1"] = "v1"
					return nil
				}},
			},
		}

		data, err := o.HandleOIDCCallback(context.TODO(), code)
		require.NoError(t, err)
		m := make(map[string]string)
		require.NoError(t, json.Unmarshal(data, &m))
		require.Equal(t, 1, len(m))
		require.Equal(t, "v1", m["k1"])
	})

	t.Run("error exchanging auth code", func(t *testing.T) {
		config, cleanup := config()
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{
				exchangeErr: errors.New("test"),
			}
		}
		_, err = svc.HandleOIDCCallback(context.TODO(), "code")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to exchange oauth2 code for token")
	})

	t.Run("error missing id_token", func(t *testing.T) {
		config, cleanup := config()
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{}},
		}
		_, err = svc.HandleOIDCCallback(context.TODO(), "code")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing id_token")
	})

	t.Run("error id_token verification", func(t *testing.T) {
		config, cleanup := config()
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyErr: errors.New("test")},
		}
		_, err = svc.HandleOIDCCallback(context.TODO(), "code")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify id_token")
	})

	t.Run("error scanning id_token claims", func(t *testing.T) {
		config, cleanup := config()
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{oidcClaimsErr: errors.New("test")}},
		}
		_, err = svc.HandleOIDCCallback(context.TODO(), "code")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to extract user data from id_token")
	})
}

func TestOIDCProviderImpl(t *testing.T) {
	o := oidcProviderImpl{&oidc.Provider{}}
	require.Empty(t, o.Endpoint())
	require.NotEmpty(t, o.Verifier(&oidc.Config{}))
}

func TestVerifierImpl(t *testing.T) {
	v := verifierImpl{}
	_, err := v.Verify(context.TODO(), "t1")
	require.Error(t, err)
}

func TestOauth2ConfigImpl(t *testing.T) {
	o := oauth2ConfigImpl{oc: &oauth2.Config{}}
	_, err := o.Exchange(context.Background(), "t1")
	require.Error(t, err)
}

type mockOIDCProvider struct {
	baseURL  string
	verifier *mockVerifier
}

func (m *mockOIDCProvider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth2/auth", m.baseURL),
		TokenURL: fmt.Sprintf("%s/oauth2/token", m.baseURL),
	}
}

func (m *mockOIDCProvider) Verifier(*oidc.Config) verifier {
	return m.verifier
}

type mockVerifier struct {
	verifyVal idToken
	verifyErr error
}

func (m *mockVerifier) Verify(ctx context.Context, token string) (idToken, error) {
	return m.verifyVal, m.verifyErr
}

func config() (*Config, func()) {
	path, oidcCleanup := newTestOIDCProvider()

	return &Config{
			OIDCProviderURL:  path,
			OIDCClientID:     uuid.New().String(),
			OIDCClientSecret: uuid.New().String(),
			OIDCCallbackURL:  "http://test.com",
		}, func() {
			oidcCleanup()
		}
}

func newTestOIDCProvider() (string, func()) {
	h := &testOIDCProvider{}
	srv := httptest.NewServer(h)
	h.baseURL = srv.URL

	return srv.URL, srv.Close
}

type oidcConfigJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type testOIDCProvider struct {
	baseURL string
}

func (t *testOIDCProvider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	response, err := json.Marshal(&oidcConfigJSON{
		Issuer:      t.baseURL,
		AuthURL:     fmt.Sprintf("%s/oauth2/auth", t.baseURL),
		TokenURL:    fmt.Sprintf("%s/oauth2/token", t.baseURL),
		JWKSURL:     fmt.Sprintf("%s/oauth2/certs", t.baseURL),
		UserInfoURL: fmt.Sprintf("%s/oauth2/userinfo", t.baseURL),
		Algorithms:  []string{"RS256"},
	})
	if err != nil {
		panic(err)
	}

	_, err = w.Write(response)
	if err != nil {
		panic(err)
	}
}

type mockOAuth2Config struct {
	authCodeFunc func(string, ...oauth2.AuthCodeOption) string
	exchangeVal  oauth2Token
	exchangeErr  error
}

func (m *mockOAuth2Config) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return m.authCodeFunc(state, options...)
}

func (m *mockOAuth2Config) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return m.exchangeVal, m.exchangeErr
}

type mockToken struct {
	oauth2Claim    interface{}
	oidcClaimsFunc func(v interface{}) error
	oidcClaimsErr  error
}

func (m *mockToken) Extra(_ string) interface{} {
	if m.oauth2Claim != nil {
		return m.oauth2Claim
	}

	return nil
}

func (m *mockToken) Claims(v interface{}) error {
	if m.oidcClaimsFunc != nil {
		return m.oidcClaimsFunc(v)
	}

	return m.oidcClaimsErr
}
