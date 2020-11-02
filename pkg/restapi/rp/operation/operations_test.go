/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

const (
	validVP = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		"type": "VerifiablePresentation",
		"verifiableCredential": [{
			"@context": [
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1"
			],
			"id": "http://example.edu/credentials/1872",
			"type": "VerifiableCredential",
			"credentialSubject": {
				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
			},
			"issuer": {
				"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
				"name": "Example University"
			},
			"issuanceDate": "2010-01-01T19:23:24Z",
			"credentialStatus": {
				"id": "https://example.gov/status/24",
				"type": "CredentialStatusList2017"
			}
		}],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"refreshService": {
			"id": "https://example.edu/refresh/3732",
			"type": "ManualRefreshService2018"
		}
	}`
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 3, len(svc.GetRESTHandlers()))
	})

	t.Run("error if oidc provider is invalid", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		config.OIDCProviderURL = "INVALID"
		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if unable to open transient store", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		config.TransientStoreProvider = &mockstore.Provider{
			ErrOpenStoreHandle: errors.New("test"),
		}
		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if unable to create transient store", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		config.TransientStoreProvider = &mockstore.Provider{
			ErrCreateStore: errors.New("generic"),
		}
		_, err := New(config)
		require.Error(t, err)
	})
}

func TestVerifyVP(t *testing.T) {
	t.Run("test error from parse form missing body", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		rr := httptest.NewRecorder()
		svc.verifyVP(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse form: missing form body")
	})

	t.Run("test error from unmarshal post", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("data"))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vpDataInput"] = []string{"vp"}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal request")
	})

	t.Run("test error due to invalid form data", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("invalid form data")}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify: invalid form data")
	})

	t.Run("test verify vp failed", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		b, err := json.Marshal(edgesvcops.CredentialsVerificationFailResponse{
			Checks: []edgesvcops.CredentialsVerificationCheckResult{
				{Check: "status", Error: "status check failed"},
			},
		})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "status check failed")
	})

	t.Run("test vp html not exist", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		config.VPHTML = ""
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test resp read fail", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}

		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test success", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestCreateOIDCRequest(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		const flowType = "CreditCard"
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{createOIDCRequest: "request"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(scope, flowType))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, http.StatusOK, w.Code)
		result := &createOIDCRequestResponse{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, "request", result.Request)
	})

	t.Run("failed to create oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		const flowType = "CreditCard"
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{createOIDCRequestErr: fmt.Errorf("failed to create")}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(scope, flowType))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to create")
	})

	t.Run("bad request if scope is missing", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest("", ""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("bad request if flow type is missing", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest("test", ""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if transient store fails", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("test"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest("CreditCardStatement", "CreditCard"))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandleOIDCCallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		config, configCleanup := config(t)
		defer configCleanup()

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
			},
		}

		o, err := New(config)
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{}

		result := httptest.NewRecorder()

		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("failed to handle oidc callback", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		config, configCleanup := config(t)
		defer configCleanup()

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
			},
		}

		o, err := New(config)
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{handleOIDCCallbackErr: fmt.Errorf("failed to handle oidc callback")}

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error missing state", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("", "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error missing code", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", ""))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error invalid state parameter", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("generic transient store error", func(t *testing.T) {
		state := uuid.New().String()
		config, cleanup := config(t)
		defer cleanup()

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
				ErrGet: errors.New("generic"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("test vp html not exist", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		config, configCleanup := config(t)
		defer configCleanup()
		config.DIDCOMMVPHTML = ""

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
			},
		}

		o, err := New(config)
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{}

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "unable to load html")
	})
}

func newCreateOIDCHTTPRequest(scope, flowType string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com/oauth2/request?scope=%s&flow=%s",
		scope, flowType), nil)
}

func newOIDCCallback(state, code string) (req *http.Request) {
	cookie := &http.Cookie{Name: flowTypeCookie, Value: "credit"}
	req = httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
	req.AddCookie(cookie)

	return req
}

func tmpFile(t *testing.T) (string, func()) {
	file, err := ioutil.TempFile("", "*.html")
	require.NoError(t, err)

	return file.Name(), func() { require.NoError(t, os.Remove(file.Name())) }
}

type mockOIDCClient struct {
	createOIDCRequest     string
	createOIDCRequestErr  error
	handleOIDCCallbackErr error
}

func (m *mockOIDCClient) CreateOIDCRequest(state, scope string) (string, error) {
	return m.createOIDCRequest, m.createOIDCRequestErr
}

func (m *mockOIDCClient) HandleOIDCCallback(reqContext context.Context, code string) ([]byte, error) {
	return nil, m.handleOIDCCallbackErr
}

func config(t *testing.T) (*Config, func()) {
	path, oidcCleanup := newTestOIDCProvider()
	file, fileCleanup := tmpFile(t)

	return &Config{
			OIDCProviderURL:        path,
			OIDCClientID:           uuid.New().String(),
			OIDCClientSecret:       uuid.New().String(),
			OIDCCallbackURL:        "http://test.com",
			TransientStoreProvider: memstore.NewProvider(),
			VPHTML:                 file,
			DIDCOMMVPHTML:          file,
		}, func() {
			oidcCleanup()
			fileCleanup()
		}
}

type mockHTTPClient struct {
	postValue *http.Response
	postErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.postValue, m.postErr
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
