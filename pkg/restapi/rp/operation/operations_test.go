/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
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
	memstore "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
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
                "id": "https://example.gov/status/24#94567",
                "type": "RevocationList2020Status",
                "revocationListIndex": "94567",
                "revocationListCredential": "https://example.gov/status/24"
            }
		}],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	}`
	validVC = `{
   "@context":[
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
      "https://w3id.org/vc-revocation-list-2020/v1"
   ],
   "credentialStatus":{
      "id":"https://issuer-vcs.sandbox.trustbloc.dev/trustbloc_ed25519signature2018_ed25519/status/1#0",
      "revocationListCredential":
      "https://issuer-vcs.sandbox.trustbloc.dev/trustbloc_ed25519signature2018_ed25519/status/1",
      "revocationListIndex":"0",
      "type":"RevocationList2020Status"
   },
   "credentialSubject":{
      "degree":{
         "degree":"Bachelor of Science and Arts",
         "type":"BachelorDegree"
      },
      "id":"did:trustbloc:4vSjd:EiAQcxO7cXUge_EV54by9ehz6KsDXmsRG59fLSsZiUPOJw",
      "name":"Jayden Doe"
   },
   "description":"University Degree Credential for Mr.Jayden Doe",
   "id":"http://example.com/678e0dfd-99db-418f-9fc3-6582f8b18bd0",
   "issuanceDate":"2021-08-10T14:06:39.829544433Z",
   "issuer":{
      "id":"did:orb:uAAA:EiDNtWtOHhGu8yRExtT0Ur7g9R-Z575i-8jFS_-PdrKJvg",
      "name":"trustbloc_ed25519signature2018_ed25519"
   },
   "name":"University Degree Credential",
   "type":[
      "VerifiableCredential",
      "UniversityDegreeCredential"
   ]
}`
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 5, len(svc.GetRESTHandlers()))
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
			ErrOpenStore: errors.New("test"),
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
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("data")),
		}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vpDataInput"] = []string{"vp"}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify: unmarshal request")
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
				{Check: "credentialStatus", Error: "status check failed"},
			},
		})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader(string(b))),
		}}

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
			StatusCode: http.StatusOK, Body: nil,
		}}

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
			StatusCode: http.StatusOK, Body: nil,
		}}

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
			StatusCode: http.StatusOK, Body: nil,
		}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		m["checks"] = []string{"proof,credentialStatus"}
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

	t.Run("returns waci oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		const flowType = "CreditCard"
		config, cleanup := config(t)
		defer cleanup()
		svc, err := New(config)
		require.NoError(t, err)
		svc.waciOIDCClient = &mockOIDCClient{createOIDCRequest: "request"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("http://example.com/oauth2/request?scope=%s&flow=%s&demoType=%s",
				scope, flowType, waciDemoType), nil))
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
			OpenStoreReturn: &mockstore.Store{
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

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		config.TransientStoreProvider = &mockstore.Provider{
			OpenStoreReturn: storeToReturnFromMockProvider,
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

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		config.TransientStoreProvider = &mockstore.Provider{
			OpenStoreReturn: storeToReturnFromMockProvider,
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
			OpenStoreReturn: &mockstore.Store{
				GetReturn: []byte(state),
				ErrGet:    errors.New("generic"),
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

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		config.TransientStoreProvider = &mockstore.Provider{
			OpenStoreReturn: storeToReturnFromMockProvider,
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

func TestVerifyDIDAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil,
		}}

		reqBytes, err := json.Marshal(&verifyPresentationRequest{
			Checks:    []string{},
			Domain:    uuid.NewString(),
			Challenge: uuid.NewString(),
			VP:        []byte(validVP),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyPresentationPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyPresentation(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("bad request", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyPresentationPath, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyPresentation(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("verification failure", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		reqBytes, err := json.Marshal(&verifyPresentationRequest{
			Checks:    []string{},
			Domain:    uuid.NewString(),
			Challenge: uuid.NewString(),
			VP:        []byte(validVP),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyPresentationPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyPresentation(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify vp")

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: nil,
		}}

		rr = httptest.NewRecorder()

		svc.verifyPresentation(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader("invalid signature")),
		}}

		req, err = http.NewRequest(http.MethodPost, verifyPresentationPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr = httptest.NewRecorder()

		svc.verifyPresentation(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify presentation")
	})
}

func TestVerifyCredential(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil,
		}}

		reqBytes, err := json.Marshal(&verifyCredentialRequest{
			Checks: []string{},
			VC:     []byte(validVC),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyCredential(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("bad request", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialPath, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyCredential(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("verification failure", func(t *testing.T) {
		config, cleanup := config(t)
		defer cleanup()

		svc, err := New(config)
		require.NoError(t, err)

		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		reqBytes, err := json.Marshal(&verifyCredentialRequest{
			Checks: []string{},
			VC:     []byte(validVC),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyPresentationPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyCredential(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify vc")

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: nil,
		}}

		rr = httptest.NewRecorder()

		svc.verifyCredential(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")

		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader("invalid signature")),
		}}

		req, err = http.NewRequest(http.MethodPost, verifyCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr = httptest.NewRecorder()

		svc.verifyCredential(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify credential")
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
	t.Helper()

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
	t.Helper()

	path, oidcCleanup := newTestOIDCProvider()
	file, fileCleanup := tmpFile(t)

	return &Config{
			OIDCProviderURL:        path,
			OIDCClientID:           uuid.New().String(),
			OIDCClientSecret:       uuid.New().String(),
			OIDCCallbackURL:        "http://test.com",
			WACIOIDCProviderURL:    path,
			WACIOIDCClientID:       uuid.New().String(),
			WACIOIDCClientSecret:   uuid.New().String(),
			WACIOIDCCallbackURL:    "http://test.com",
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
