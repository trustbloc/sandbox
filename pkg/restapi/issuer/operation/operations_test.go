/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
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
	"github.com/gorilla/mux"
	memstore "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/sandbox/pkg/token"
)

const authHeader = "Bearer ABC"

const testCredentialRequest = `{
   "@context": [
		"https://www.w3.org/2018/credentials/v1", 
		"https://www.w3.org/2018/credentials/examples/v1"
	],
   "type":[
      "VerifiableCredential",
      "UniversityDegreeCredential"
   ],
   "issuer": {
		"id": "did:trustbloc:testnet.trustbloc.local:EiABBmUZ7Jjp-mlxWJInqp3Ak2v82QQtCdIUS5KSTNGq9Q==",
		"name": "myprofile_ud1"
	},
	"issuanceDate": "2020-03-16T22:37:26.544Z",
   "credentialSubject":{
      "id":"did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree":{
         "type":"BachelorDegree",
         "university":"MIT"
      },
      "name":"Jayden Doe",
      "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
   }
}`

const profileData = `{
   "name":"issuer",
   "did":"did:local:abc",
   "uri":"https://example.com/credentials",
   "signatureType":"Ed25519Signature2018",
   "signatureRepresentation":0,
   "creator":"did:local:abc#key-1",
   "created":"2020-04-03T17:27:43.012324Z",
   "didPrivateKey":""
}`

const foo = `{
   "id":1,
   "userid":"100",
   "name":"Foo Bar",
   "email":"foo@bar.com",
   "vcmetadata":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1"
      ],
      "name":"foo",
      "description":"foo bar"
   },
   "vccredentialsubject":{
      "id":"1234568",
      "issuedDate":"2020-05-27",
      "expiryDate":"2025-05-26",
      "address":"4726 Pine Street, Toronto - A1B 2C3"
   }
}`
const jsonArray = `[{}]`

const (
	holder    = "did:example.com"
	domain    = "issuer.interop.transmute.world"
	challenge = "3970cad8-14ff-4ac1-ada9-0995c862df2e"
	authResp  = `{
    "@context": "https://www.w3.org/2018/credentials/v1",
    "type": "VerifiablePresentation",
    "holder": "did:example.com",
    "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-04-21T21:25:18Z",
        "verificationMethod": "did:example.com#key-1",
        "proofPurpose": "authentication",
        "challenge": "3970cad8-14ff-4ac1-ada9-0995c862df2e",
        "domain": "issuer.interop.transmute.world",
        "jws": "6wDkNVRBs3zebe_PSIROTN3K8hBfE18ZI-Ieg_9KYI5-sDA"
    }
}`
)

const authRespWithoutChallenge = `{
    "@context": "https://www.w3.org/2018/credentials/v1",
    "type": "VerifiablePresentation",
    "holder": "did:example.com",
    "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-04-21T21:25:18Z",
        "verificationMethod": "did:example.com#key-1",
        "proofPurpose": "authentication",
        "domain": "issuer.interop.transmute.world",
        "jws": "6wDkNVRBs3zebe_PSIROTN3K8hBfE18ZI-Ieg_9KYI5-sDA"
    }
}`

const authRespWithoutDomain = `{
    "@context": "https://www.w3.org/2018/credentials/v1",
    "type": "VerifiablePresentation",
    "holder": "did:example.com",
    "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-04-21T21:25:18Z",
        "verificationMethod": "did:example.com#key-1",
        "proofPurpose": "authentication",
        "challenge": "3970cad8-14ff-4ac1-ada9-0995c862df2e",
        "jws": "6wDkNVRBs3zebe_PSIROTN3K8hBfE18ZI-Ieg_9KYI5-sDA"
    }
}`

const assuranceData = `{
	  "data":{
		  "document_number":"123-456-789",
		  "evidence_id":"d4d18a776cc6",
		  "comments":"DL verified physically at Station #531785"
	  },
	  "metadata":{
		  "contexts":[
			 "https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld"
		  ],
		  "scopes":[
			 "DrivingLicenseEvidence"
		  ],
		  "name":"Drivers License Evidence",
		  "description":"Drivers License Evidence for John Smith"
	  }
	}`

const validVP = `{
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

func TestController_New(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		op, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("test new - error", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStore: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer store provider : store open error")
		require.Nil(t, op)

		op, err = New(&Config{StoreProvider: &mockstorage.Provider{}, OIDCProviderURL: "url"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create oidc client")
		require.Nil(t, op)
	})
}

func TestOperation_Login(t *testing.T) {
	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, login, cfg)

	buff, status, err := handleRequest(handler, nil, login, true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "vcs profile is empty")
	require.Equal(t, http.StatusBadRequest, status)

	buff, status, err = handleRequest(handler, nil, login+"?scope=test&vcsProfile=vc-issuer-1", true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestAuth(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, authPath+"?scope=test&callbackURL=/abc", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.auth(rr, req)
		require.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	})

	t.Run("missing scope", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, authPath, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.auth(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "scope is mandatory")
	})

	t.Run("missing callbackURL", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, authPath+"?scope=test", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.auth(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "callbackURL is mandatory")
	})
}

func TestSearch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
		})
		require.NoError(t, err)

		txnID := uuid.NewString()

		dataBytes, err := json.Marshal(&txnData{})
		require.NoError(t, err)

		err = svc.store.Put(txnID, dataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, searchPath+"?txnID="+txnID, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.search(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("missing txnID", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, searchPath, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.search(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "txnID is mandatory")
	})

	t.Run("no txn data", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, searchPath+"?txnID="+uuid.NewString(), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.search(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get txn data")
	})

	t.Run("no user data", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		txnID := uuid.NewString()

		dataBytes, err := json.Marshal(&txnData{})
		require.NoError(t, err)

		err = svc.store.Put(txnID, dataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, searchPath+"?txnID="+txnID, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.search(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user data")
	})
}

func TestOperation_settings(t *testing.T) {
	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, settings, cfg)

	buff, status, err := handleRequest(handler, nil, settings, false)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "vcs profile is empty")
	require.Equal(t, http.StatusBadRequest, status)

	buff, status, err = handleRequest(handler, nil, settings+"?scope=test&vcsProfile=vc-issuer-1", false)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_Login3(t *testing.T) {
	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, login, cfg)

	req, err := http.NewRequest(handler.Method(), login+"?scope=test&vcsProfile=vc-issuer-1", bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	require.NoError(t, err)
	require.Contains(t, rr.Body.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, rr.Code)
}

func TestOperation_initDIDCommConnection(t *testing.T) {
	cfg := &Config{
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, didcommInit, cfg)

	buf, status, err := handleRequest(handler, nil,
		didcommInit+"?didCommScope=CreditCardStatement&adapterProfile=adapter-123&assuranceScope=dlevidence", true)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "Found")
	require.Equal(t, http.StatusFound, status)

	buf, status, err = handleRequest(handler, nil,
		didcommInit+"?didCommScope=CreditCardStatement&adapterProfile=adapter-123", true)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "Found")
	require.Equal(t, http.StatusFound, status)

	buf, status, err = handleRequest(handler, nil,
		didcommInit+"?didCommScope=CreditCardStatement&assuranceScope=dlevidence", true)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "missing adapterProfile")
	require.Equal(t, http.StatusBadRequest, status)

	buf, status, err = handleRequest(handler, nil,
		didcommInit+"?adapterProfile=adapter-123&assuranceScope=dlevidence", true)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "missing didCommScope")
	require.Equal(t, http.StatusBadRequest, status)
}

func TestOperation_getTokenInfo(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	op, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		req.Header.Set("Authorization", "Bearer token")

		op.tokenResolver = &mockTokenResolver{
			info: token.Introspection{
				Active: true,
			},
			err: nil,
		}

		rw := httptest.NewRecorder()

		info, tok, err := op.getTokenInfo(rw, req)
		require.NoError(t, err)
		require.Equal(t, "token", tok.AccessToken)
		require.Equal(t, true, info.Active)
	})

	t.Run("failure: Authorization header does not contain Bearer token", func(t *testing.T) {
		req.Header.Set("Authorization", "Wrong token")

		op.tokenResolver = &mockTokenResolver{
			info: token.Introspection{
				Active: true,
			},
			err: nil,
		}

		rw := httptest.NewRecorder()

		_, _, err := op.getTokenInfo(rw, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing bearer token")
		require.Equal(t, http.StatusUnauthorized, rw.Code)
	})

	t.Run("failure: token fails to resolve", func(t *testing.T) {
		req.Header.Set("Authorization", "Bearer token")

		op.tokenResolver = &mockTokenResolver{
			err: fmt.Errorf("token resolve error"),
		}

		rw := httptest.NewRecorder()

		_, _, err := op.getTokenInfo(rw, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token resolve error")
		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("failure: token is invalid", func(t *testing.T) {
		req.Header.Set("Authorization", "Bearer token")

		op.tokenResolver = &mockTokenResolver{
			info: token.Introspection{
				Active: false,
			},
			err: nil,
		}
		rw := httptest.NewRecorder()

		_, _, err := op.getTokenInfo(rw, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token is invalid")
		require.Equal(t, http.StatusUnauthorized, rw.Code)
	})
}

func TestOperation_getIDHandler(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "[%s]", foo)
		fmt.Fprintln(w)
	}))
	defer cms.Close()

	cfg := Config{
		CMSURL:        cms.URL,
		StoreProvider: &mockstorage.Provider{},
		TokenResolver: &mockTokenResolver{
			info: token.Introspection{
				Active:  true,
				Subject: "test-user",
			},
			err: nil,
		},
		TokenIssuer: &mockTokenIssuer{
			err: nil,
		},
	}

	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	t.Run("success", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommUserEndpoint, &cfg)

		_, status, err := handleRequest(handler, headers, didcommUserEndpoint, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("failure: no token", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommUserEndpoint, &cfg)

		_, status, err := handleRequest(handler, nil, didcommUserEndpoint, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("failure: cms error", func(t *testing.T) {
		cms2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[{}, {}, {}]")
			fmt.Fprintln(w)
		}))
		defer cms2.Close()

		cfg2 := Config{
			CMSURL:        cms2.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
		}

		handler := getHandlerWithConfig(t, didcommUserEndpoint, &cfg2)

		_, status, err := handleRequest(handler, headers, didcommUserEndpoint, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
	})
}

func TestOperation_getDIDCommScopes(t *testing.T) {
	op := Operation{
		didcommScopes: map[string]struct{}{
			"scope1": {},
			"scope2": {},
			"scope3": {},
		},
	}

	out := op.getDIDCommScopes("scope2 scope3 scope4")
	require.Len(t, out, 2)
	require.Contains(t, out, "scope2")
	require.Contains(t, out, "scope3")
}

func TestOperation_getCredUsingToken(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "[%s]", foo)
		fmt.Fprintln(w)
	}))
	defer cms.Close()

	cfg := Config{
		CMSURL:        cms.URL,
		StoreProvider: &mockstorage.Provider{},
		TokenResolver: &mockTokenResolver{
			info: token.Introspection{
				Active:  true,
				Subject: "test-user",
				Scope:   "TestScope",
			},
			err: nil,
		},
		TokenIssuer: &mockTokenIssuer{
			err: nil,
		},
		didcommScopes: map[string]struct{}{
			"TestScope": {},
		},
	}

	headers := make(map[string]string)
	headers["Authorization"] = "Bearer TestToken"

	t.Run("success", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommCredential, &cfg)

		_, status, err := handleRequest(handler, headers, didcommCredential, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("failure: invalid token", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommCredential, &Config{
			CMSURL:        cms.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active: false,
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
			didcommScopes: map[string]struct{}{
				"TestScope": {},
			},
		})

		_, status, err := handleRequest(handler, headers, didcommCredential, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("failure - token does not have valid cred scope", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommCredential, &Config{
			CMSURL:        cms.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
					Scope:   "TestScope",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
		})

		body, status, err := handleRequest(handler, headers, didcommCredential, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "no valid credential scope")
	})

	t.Run("failure: cms error", func(t *testing.T) {
		cms2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[{}, {}, {}]")
			fmt.Fprintln(w)
		}))
		defer cms2.Close()

		handler := getHandlerWithConfig(t, didcommCredential, &Config{
			CMSURL:        cms2.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
					Scope:   "TestScope",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
			didcommScopes: map[string]struct{}{
				"TestScope": {},
			},
		})

		body, status, err := handleRequest(handler, headers, didcommCredential, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "failed to get cms data")
	})
}

func TestOperation_getAssuranceUsingToken(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "[%s]", foo)
		fmt.Fprintln(w)
	}))
	defer cms.Close()

	cfg := Config{
		CMSURL:        cms.URL,
		StoreProvider: &mockstorage.Provider{},
		TokenResolver: &mockTokenResolver{
			info: token.Introspection{
				Active:  true,
				Subject: "test-user",
				Scope:   "TestScope",
			},
			err: nil,
		},
		TokenIssuer: &mockTokenIssuer{
			err: nil,
		},
		didcommScopes: map[string]struct{}{
			"TestScope": {},
		},
		assuranceScopes: map[string]string{
			"TestScope": "TestAssurance",
		},
	}

	headers := make(map[string]string)
	headers["Authorization"] = "Bearer TestToken"

	t.Run("success", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommAssuranceData, &cfg)

		_, status, err := handleRequest(handler, headers, didcommAssuranceData, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("failure: invalid token", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommAssuranceData, &Config{
			CMSURL:        cms.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active: false,
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
			didcommScopes: map[string]struct{}{
				"TestScope": {},
			},
			assuranceScopes: map[string]string{
				"TestScope": "TestAssurance",
			},
		})

		_, status, err := handleRequest(handler, headers, didcommAssuranceData, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("failure: cms error getting user", func(t *testing.T) {
		cms2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[{}, {}, {}]")
			fmt.Fprintln(w)
		}))
		defer cms2.Close()

		handler := getHandlerWithConfig(t, didcommAssuranceData, &Config{
			CMSURL:        cms2.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
					Scope:   "TestScope",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
			didcommScopes: map[string]struct{}{
				"TestScope": {},
			},
			assuranceScopes: map[string]string{
				"TestScope": "TestAssurance",
			},
		})

		body, status, err := handleRequest(handler, headers, didcommAssuranceData, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "failed to get cms user")
	})

	t.Run("failure - token does not have valid cred scope", func(t *testing.T) {
		handler := getHandlerWithConfig(t, didcommAssuranceData, &Config{
			CMSURL:        cms.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
					Scope:   "TestScope",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
		})

		body, status, err := handleRequest(handler, headers, didcommAssuranceData, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "no assurance scope")
	})

	t.Run("failure: cms error getting user data", func(t *testing.T) {
		cms2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.String(), "/users"):
				fmt.Fprintf(w, "[%s]", foo)
			case strings.Contains(r.URL.String(), "?userid"):
				fmt.Fprintf(w, "[{}, {}, {}]")
			}
			fmt.Fprintln(w)
		}))
		defer cms2.Close()

		handler := getHandlerWithConfig(t, didcommAssuranceData, &Config{
			CMSURL:        cms2.URL,
			StoreProvider: &mockstorage.Provider{},
			TokenResolver: &mockTokenResolver{
				info: token.Introspection{
					Active:  true,
					Subject: "test-user",
					Scope:   "TestScope",
				},
				err: nil,
			},
			TokenIssuer: &mockTokenIssuer{
				err: nil,
			},
			didcommScopes: map[string]struct{}{
				"TestScope": {},
			},
			assuranceScopes: map[string]string{
				"TestScope": "TestAssurance",
			},
		})

		body, status, err := handleRequest(handler, headers, didcommAssuranceData, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "failed to get assurance data")
	})
}

func TestOperation_Callback(t *testing.T) {
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	t.Run("test callback - non didcomm", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte(profileData))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			DIDAuthHTML:   file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}
		handler := getHandlerWithConfig(t, callback, cfg)

		_, status, err := handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		_, status, err = handleRequest(handler, headers, callback+"?error=access_denied", true)
		require.NoError(t, err)
		require.Equal(t, http.StatusTemporaryRedirect, status)

		// test ledger cookie not found
		cfg = &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(), DIDAuthHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}
		handler = getHandlerWithConfig(t, callback, cfg)

		body, status, err := handleRequest(handler, headers, callback, false)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "failed to get cookie")

		// test html not exist
		cfg = &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: "",
			StoreProvider: &mockstorage.Provider{},
		}
		handler = getHandlerWithConfig(t, callback, cfg)

		body, status, err = handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "unable to load html")

		// profile doesnt exists
		r := mux.NewRouter()
		r.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err = writer.Write([]byte("invalid-data"))
			if err != nil {
				panic(err)
			}
		})

		cfg = &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: httptest.NewServer(r).URL, ReceiveVCHTML: file.Name(),
			DIDAuthHTML:   file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}
		handler = getHandlerWithConfig(t, callback, cfg)

		body, status, err = handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "failed to create credential: retrieve profile")

		// cms error
		cmsRouter := mux.NewRouter()
		cmsRouter.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		})

		cfg = &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: httptest.NewServer(cmsRouter).URL, VCSURL: httptest.NewServer(r).URL, ReceiveVCHTML: file.Name(),
			DIDAuthHTML:   file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}
		handler = getHandlerWithConfig(t, callback, cfg)

		body, status, err = handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "failed to get cms data")
	})

	t.Run("with callbackURL cookie", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, callback, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: callbackURLCookie, Value: "/abc"})

		rr := httptest.NewRecorder()

		svc.callback(rr, req)
		require.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	})

	t.Run("with callbackURL cookie - save txn data error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{
				ErrPut: errors.New("save error"),
			}},
			CMSURL: cms.URL,
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, callback, nil)
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: callbackURLCookie, Value: "/abc"})

		rr := httptest.NewRecorder()

		svc.callback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save txn data")
	})
}

func TestOperation_GenerateVC(t *testing.T) {
	t.Run("generate VC success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "users") {
				fmt.Fprintf(w, "[%s]", foo)
				fmt.Fprintln(w)
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		headers := make(map[string]string)
		headers["Authorization"] = authHeader

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}

		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Header = make(map[string][]string)
		req.Form.Add("cred", testCredentialRequest)
		req.Form.Add("holder", holder)
		req.Form.Add("authresp", authResp)
		req.Form.Add("domain", domain)
		req.Form.Add("challenge", challenge)

		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})

		svc.generateVC(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("generate VC - validations", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		req := &http.Request{Form: m}
		req.Header = make(map[string][]string)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "named cookie not present")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request argument: invalid 'cred'")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Add("cred", "{}")
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request argument: invalid 'holder'")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Add("holder", holder)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request argument: invalid 'authresp'")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Add("authresp", "{}")
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request argument: invalid 'domain'")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Add("domain", domain)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request argument: invalid 'challenge'")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Set("authresp", authResp)
		req.Form.Set("holder", "")
		req.Form.Set("domain", domain)
		req.Form.Set("challenge", challenge)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "DID Auth failed: invalid auth response, invalid holder proof")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Set("authresp", authResp)
		req.Form.Set("holder", holder)
		req.Form.Set("domain", "")
		req.Form.Set("challenge", challenge)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "DID Auth failed: invalid proof and challenge in response")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Set("authresp", authResp)
		req.Form.Set("holder", holder)
		req.Form.Set("domain", domain)
		req.Form.Set("challenge", "")
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "DID Auth failed: invalid proof and challenge in response")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Set("authresp", authResp)
		req.Form.Set("challenge", challenge)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create verifiable credential")

		rr = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})
		req.Form.Set("cred", testCredentialRequest)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create verifiable credential")
	})

	t.Run("Validate Auth Resp - validations", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NotNil(t, svc)
		require.NoError(t, err)

		err = svc.validateAuthResp([]byte(authRespWithoutChallenge), holder, domain, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth response proof, missing challenge")

		err = svc.validateAuthResp([]byte(authRespWithoutDomain), holder, domain, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth response proof, missing domain")
	})

	t.Run("generate VC - store error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "users") {
				fmt.Fprintf(w, "[%s]", foo)
				fmt.Fprintln(w)
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		})

		router.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		headers := make(map[string]string)
		headers["Authorization"] = authHeader

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{},
		}

		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Header = make(map[string][]string)
		req.Form.Add("cred", testCredentialRequest)
		req.Form.Add("holder", holder)
		req.Form.Add("authresp", authResp)
		req.Form.Add("domain", domain)
		req.Form.Add("challenge", challenge)

		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})

		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to store credential")
	})

	t.Run("generate VC - template errors", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "users") {
				fmt.Fprintf(w, "[%s]", foo)
				fmt.Fprintln(w)
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		headers := make(map[string]string)
		headers["Authorization"] = authHeader

		cfg := &Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{},
		}

		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Header = make(map[string][]string)
		req.Form.Add("cred", testCredentialRequest)
		req.Form.Add("holder", holder)
		req.Form.Add("authresp", authResp)
		req.Form.Add("domain", domain)
		req.Form.Add("challenge", challenge)

		req.AddCookie(&http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"})

		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})
}

func TestOperation_Callback_ExchangeCodeError(t *testing.T) {
	svc, err := New(&Config{
		TokenIssuer:   &mockTokenIssuer{err: errors.New("exchange code error")},
		TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	})
	require.NotNil(t, svc)
	require.NoError(t, err)

	handler := handlerLookup(t, svc, callback)

	body, status, err := handleRequest(handler, nil, callback, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body.String(), "failed to exchange code for token")
	require.Contains(t, body.String(), "exchange code error")
}

func TestOperation_Callback_TokenIntrospectionError(t *testing.T) {
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	svc, err := New(&Config{
		TokenIssuer:   &mockTokenIssuer{},
		TokenResolver: &mockTokenResolver{err: errors.New("token info error")},
		StoreProvider: &mockstorage.Provider{},
	})
	require.NoError(t, err)
	require.NotNil(t, svc)

	handler := handlerLookup(t, svc, callback)
	body, status, err := handleRequest(handler, headers, callback, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body.String(), "failed to get token info")
	require.Contains(t, body.String(), "token info error")
}

func TestOperation_Callback_GetCMSData_Error(t *testing.T) {
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "cms",
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, callback, cfg)

	data, status, err := handleRequest(handler, headers, callback, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, data.String(), "unsupported protocol scheme")
}

func TestOperation_Callback_CreateCredential_Error(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, jsonArray)
	}))
	defer cms.Close()

	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: cms.URL, VCSURL: "vcs",
		StoreProvider: &mockstorage.Provider{},
	}
	handler := getHandlerWithConfig(t, callback, cfg)

	data, status, err := handleRequest(handler, headers, callback, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, data.String(), "unsupported protocol scheme")
}

func TestOperation_StoreCredential(t *testing.T) {
	t.Run("store credential success", func(t *testing.T) {
		vcs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "{}")
		}))
		defer vcs.Close()
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{},
		})
		require.NoError(t, err)

		err = svc.storeCredential([]byte(testCredentialRequest), "")
		require.NoError(t, err)
	})
	t.Run("store credential error invalid url ", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			VCSURL:        "%%&^$",
			StoreProvider: &mockstorage.Provider{},
		})
		require.NoError(t, err)

		err = svc.storeCredential([]byte(testCredentialRequest), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL escape")
	})
	t.Run("store credential error incorrect status", func(t *testing.T) {
		vcs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, "{}")
		}))
		defer vcs.Close()
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{},
		})
		require.NoError(t, err)

		err = svc.storeCredential([]byte(testCredentialRequest), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "201 Created")
	})
}

func TestOperation_GetCMSData_InvalidURL(t *testing.T) {
	svc, err := New(&Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "xyz:cms",
		StoreProvider: &mockstorage.Provider{},
	})
	require.NotNil(t, svc)
	require.NoError(t, err)

	_, data, err := svc.getCMSData(&oauth2.Token{}, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	require.Nil(t, data)
}

func TestOperation_GetCMSData_InvalidHTTPRequest(t *testing.T) {
	svc, err := New(&Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "http://cms\\",
		StoreProvider: &mockstorage.Provider{},
	})
	require.NotNil(t, svc)
	require.NoError(t, err)

	userID, data, err := svc.getCMSData(&oauth2.Token{}, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
	require.Nil(t, data)
	require.Empty(t, userID)
}

func TestOperation_CreateCredential_Errors(t *testing.T) {
	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	}

	var subject map[string]interface{} = make(map[string]interface{})
	subject["id"] = "1"

	t.Run("unsupported protocol scheme", func(t *testing.T) {
		cfg.VCSURL = "xyz:vcs"
		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		data, err := svc.createCredential(testCredentialRequest, authResp, holder, domain, challenge, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
		require.Nil(t, data)
	})
	t.Run("invalid http request", func(t *testing.T) {
		cfg.VCSURL = "http://vcs\\"
		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		data, err := svc.createCredential(testCredentialRequest, authResp, holder, domain, challenge, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, data)
	})
	t.Run("invalid subject map - contains channel", func(t *testing.T) {
		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		data, err := svc.createCredential(testCredentialRequest+",", authResp, holder, domain, challenge, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, data)
	})
}

func TestOperation_GetCMSUser(t *testing.T) {
	cfg := &Config{
		TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{},
	}

	t.Run("test success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		cfg.CMSURL = cms.URL
		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		userID, data, err := svc.getCMSData(&oauth2.Token{}, "", "")
		require.NoError(t, err)
		require.Equal(t, data["email"], "foo@bar.com")
		require.NotEmpty(t, userID)
	})
	t.Run("no user found", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "[]")
		}))
		defer cms.Close()

		cfg.CMSURL = cms.URL

		svc, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, svc)

		userID, data, err := svc.getCMSData(&oauth2.Token{}, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "user not found")
		require.Nil(t, data)
		require.Empty(t, userID)
	})
}

func TestOperation_UnmarshalUser(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		user, err := unmarshalUser([]byte(fmt.Sprintf("[%s]", foo)))
		require.NoError(t, err)
		require.Equal(t, user.Email, "foo@bar.com")
	})
	t.Run("json unmarshal error", func(t *testing.T) {
		data, err := unmarshalUser([]byte("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, data)
	})
	t.Run("user not found", func(t *testing.T) {
		data, err := unmarshalUser([]byte("[]"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "user not found")
		require.Nil(t, data)
	})
	t.Run("multiple users error", func(t *testing.T) {
		data, err := unmarshalUser([]byte("[{},{}]"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple users found")
		require.Nil(t, data)
	})
}

func TestOperation_UnmarshalSubject(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		data, err := unmarshalSubject([]byte(`[{"email":"foo@bar.com"}]`))
		require.NoError(t, err)
		require.Equal(t, data["email"], "foo@bar.com")
	})
	t.Run("json unmarshal error", func(t *testing.T) {
		data, err := unmarshalSubject([]byte("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, data)
	})
	t.Run("record not found", func(t *testing.T) {
		data, err := unmarshalSubject([]byte("[]"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "record not found")
		require.Nil(t, data)
	})
	t.Run("multiple records error", func(t *testing.T) {
		data, err := unmarshalSubject([]byte("[{},{}]"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple records found")
		require.Nil(t, data)
	})
}

func TestOperation_SendHTTPRequest_WrongStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.NoError(t, err)

	data, err := sendHTTPRequest(req, http.DefaultClient, http.StatusInternalServerError, "tk1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "200 OK")
	require.Nil(t, data)
}

func TestGetCreditScore(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", foo)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		handler := getHandlerWithConfig(t, getCreditScore,
			&Config{StoreProvider: memstore.NewProvider(), CMSURL: cms.URL})

		_, status, err := handleRequest(handler, nil,
			getCreditScore+"?givenName=first&familyName=last&didCommScope=scope&adapterProfile=profile", true)
		require.NoError(t, err)
		require.Equal(t, http.StatusFound, status)
	})

	t.Run("test failed to get cms data", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer cms.Close()

		handler := getHandlerWithConfig(t, getCreditScore,
			&Config{StoreProvider: memstore.NewProvider(), CMSURL: cms.URL})

		body, status, err := handleRequest(handler, nil,
			getCreditScore+"?givenName=first&familyName=last&didCommScope=scope&adapterProfile=profile", true)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "failed to get cms data")
	})
}

func TestCreateOIDCRequest(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		svc, err := New(&Config{StoreProvider: memstore.NewProvider()})
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{createOIDCRequest: "request"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(scope))
		require.Equal(t, http.StatusOK, w.Code)
		result := &createOIDCRequestResponse{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, "request", result.Request)
	})

	t.Run("failed to create oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		svc, err := New(&Config{StoreProvider: memstore.NewProvider()})
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{createOIDCRequestErr: fmt.Errorf("failed to create")}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(scope))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to create")
	})

	t.Run("bad request if scope is missing", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: memstore.NewProvider()})
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if transient store fails", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{
			ErrPut: errors.New("test"),
		}}})
		require.NoError(t, err)
		svc.oidcClient = &mockOIDCClient{}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest("CreditCardStatement"))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandleOIDCCallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		o, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider},
			DIDCOMMVPHTML: file.Name(),
		})
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{}

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("failed to handle oidc callback", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		o, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider},
			DIDCOMMVPHTML: file.Name(),
		})
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{handleOIDCCallbackErr: fmt.Errorf("failed to handle oidc callback")}

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error missing state", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{StoreProvider: memstore.NewProvider(), DIDCOMMVPHTML: file.Name()})
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("", "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error missing code", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{StoreProvider: memstore.NewProvider(), DIDCOMMVPHTML: file.Name()})
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", ""))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("error invalid state parameter", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{StoreProvider: memstore.NewProvider(), DIDCOMMVPHTML: file.Name()})
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("generic transient store error", func(t *testing.T) {
		state := uuid.New().String()

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{
			OpenStoreReturn: &mockstorage.Store{
				GetReturn: []byte(state),
				ErrGet:    errors.New("generic"),
			},
		}, DIDCOMMVPHTML: file.Name()})
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusOK, result.Code)
	})

	t.Run("test vp html not exist", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		storeToReturnFromMockProvider, err := memstore.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(state, []byte(state))
		require.NoError(t, err)

		o, err := New(&Config{StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider}})
		require.NoError(t, err)

		o.oidcClient = &mockOIDCClient{}

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "unable to load html")
	})
}

func TestRevokeVC(t *testing.T) {
	t.Run("test error from parse form", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		svc.revokeVC(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse form")
	})

	t.Run("test error from parse presentation", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			StoreProvider: &mockstorage.Provider{},
		})
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"wrong"}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse presentation")
	})

	t.Run("test error from create http request", func(t *testing.T) {
		svc, err := New(&Config{
			TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			VCSURL:        "http://vcs\\",
			StoreProvider: &mockstorage.Provider{},
		})
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create new http request")
	})

	t.Run("test error from http post", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to update vc status")
	})

	t.Run("test vc html not exist", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		svc, err := New(&Config{VCHTML: "", VCSURL: serv.URL, StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		svc, err := New(&Config{VCHTML: file.Name(), VCSURL: serv.URL, StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}

		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestDIDCommTokenHandler(t *testing.T) {
	cfg := &Config{StoreProvider: memstore.NewProvider()}
	ops, handler := getHandlerWithOps(t, didcommToken, cfg)

	t.Run("test didcomm token handler - success", func(t *testing.T) {
		state := uuid.New().String()
		err := ops.store.Put(state, []byte(testCredentialRequest))
		require.NoError(t, err)

		req := &adapterTokenReq{
			State: state,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommToken, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp adapterTokenResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.NotEmpty(t, resp.Token)
	})

	t.Run("test didcomm token handler - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommToken, []byte("invalid-json"))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("test didcomm token handler - invalid state", func(t *testing.T) {
		req := &adapterTokenReq{
			State: uuid.New().String(),
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommToken, reqBytes)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid state")
	})

	t.Run("test didcomm token handler - success", func(t *testing.T) {
		ops, handler := getHandlerWithOps(t, didcommToken, cfg)

		state := uuid.New().String()

		ops.store = &mockstorage.Store{
			GetReturn: []byte(testCredentialRequest),
			ErrPut:    errors.New("error inserting data"),
		}

		req := &adapterTokenReq{
			State: state,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommToken, reqBytes)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to store adapter token and userID mapping")
	})
}

func TestDIDCommCallbackHandler(t *testing.T) {
	headers := make(map[string]string)
	urlFmt := didcommCallback + "?" + stateQueryParam + "=%s"

	t.Run("test didcomm callback handler - success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{DIDCommHTML: file.Name(), StoreProvider: memstore.NewProvider()}

		ops, handler := getHandlerWithOps(t, didcommCallback, cfg)

		state := uuid.New().String()
		err = ops.store.Put(state, []byte(uuid.New().String()))
		require.NoError(t, err)

		_, status, err := handleRequest(handler, headers,
			fmt.Sprintf(urlFmt, state), false)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("test didcomm callback handler - html not found", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		ops, handler := getHandlerWithOps(t, didcommCallback, cfg)

		state := uuid.New().String()
		err := ops.store.Put(state, []byte(uuid.New().String()))
		require.NoError(t, err)

		respData, status, err := handleRequest(handler, headers,
			fmt.Sprintf(urlFmt, state), false)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, respData.String(), "unable to load didcomm html")
	})

	t.Run("test didcomm callback handler - validation error", func(t *testing.T) {
		cfg := &Config{StoreProvider: &mockstorage.Provider{
			OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("save error")},
		}}

		ops, err := New(cfg)
		require.NoError(t, err)

		// invalid url
		err = ops.validateAdapterCallback("http://[fe80::%31%25en0]:8080/")
		require.Error(t, err)
		require.Contains(t, err.Error(), "didcomm callback - error parsing the request url")
	})
}

func TestDIDCommCredentialHandler(t *testing.T) {
	t.Run("test didcomm credential - success", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		ops, handler := getHandlerWithOps(t, didcommCredential, cfg)

		userData := userDataMap{
			Data: []byte(testCredentialRequest),
		}

		userDataBytes, err := json.Marshal(userData)
		require.NoError(t, err)

		tkn := uuid.New().String()
		err = ops.store.Put(tkn, userDataBytes)
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommCredential, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "BachelorDegree")
	})

	t.Run("test didcomm credential - invalid request", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		_, handler := getHandlerWithOps(t, didcommCredential, cfg)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommCredential, []byte("invalid-json"))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("test didcomm credential - invalid token", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		_, handler := getHandlerWithOps(t, didcommCredential, cfg)

		req := &adapterDataReq{
			Token: uuid.New().String(),
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommCredential, reqBytes)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get token data")
	})
}

func TestDIDCommAssuranceDataHandler(t *testing.T) {
	t.Run("test didcomm assurance data - success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
		}

		ops, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		userData := userDataMap{
			Data: []byte(testCredentialRequest),
		}

		userDataBytes, err := json.Marshal(userData)
		require.NoError(t, err)

		tkn := uuid.New().String()
		err = ops.store.Put(tkn, userDataBytes)
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "123-456-789")
	})

	t.Run("test didcomm credential - invalid request", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		_, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, []byte("invalid-json"))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid request")
	})

	t.Run("test didcomm credential - invalid token", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		_, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		req := &adapterDataReq{
			Token: uuid.New().String(),
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, reqBytes)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get token data")
	})

	t.Run("test didcomm credential - invalid data from store", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		ops, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		tkn := uuid.New().String()
		err := ops.store.Put(tkn, []byte("invalid-data"))
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}
		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, reqBytes)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "user data unmarshal failed")
	})

	t.Run("test didcomm credential - cms error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer cms.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
		}

		ops, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		userData := userDataMap{
			Data: []byte(testCredentialRequest),
		}

		userDataBytes, err := json.Marshal(userData)
		require.NoError(t, err)

		tkn := uuid.New().String()
		err = ops.store.Put(tkn, userDataBytes)
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}
		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, reqBytes)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get assurance data")
	})
}

func TestVerifyDIDAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&verifyDIDAuthReq{
			Holder:      holder,
			Domain:      domain,
			Challenge:   challenge,
			DIDAuthResp: []byte(authResp),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyDIDAuthHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("bad request", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyDIDAuthHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("invalid domain", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&verifyDIDAuthReq{
			Holder:      holder,
			Domain:      uuid.New().String(),
			Challenge:   challenge,
			DIDAuthResp: []byte(authResp),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.verifyDIDAuthHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate did auth resp")
	})
}

func TestCreateCredentialHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		vcsRouter := mux.NewRouter()
		vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte(profileData))
			if err != nil {
				panic(err)
			}
		})
		vcsRouter.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(vcsRouter)

		defer vcs.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
			VCSURL:        vcs.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&createCredentialReq{
			Holder:            uuid.NewString(),
			Scope:             uuid.NewString(),
			VCSProfile:        uuid.NewString(),
			UserID:            uuid.NewString(),
			CustomSubjectData: map[string]interface{}{"name": "test123"},
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createCredentialHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("bad request", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		svc, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("cms error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer cms.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&createCredentialReq{
			Scope:      uuid.NewString(),
			VCSProfile: uuid.NewString(),
			UserID:     uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get cms user data")
	})

	t.Run("profile error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		vcsRouter := mux.NewRouter()
		vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		})

		vcs := httptest.NewServer(vcsRouter)

		defer vcs.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			CMSURL:        cms.URL,
			VCSURL:        vcs.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&createCredentialReq{
			Scope:      uuid.NewString(),
			VCSProfile: uuid.NewString(),
			UserID:     uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, verifyDIDAuthPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create credential")
	})
}

func TestGenerateCredentialHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vcsRouter := mux.NewRouter()
		vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte(profileData))
			if err != nil {
				panic(err)
			}
		})
		vcsRouter.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(vcsRouter)

		defer vcs.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			VCSURL:        vcs.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		id := uuid.NewString()

		b, err := json.Marshal(searchData{
			UserData: map[string]interface{}{},
		})
		require.NoError(t, err)

		err = svc.store.Put(id, b)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&generateCredentialReq{
			ID:         id,
			Holder:     uuid.NewString(),
			VCSProfile: uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("bad request", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "[%s]", assuranceData)
			fmt.Fprintln(w)
		}))
		defer cms.Close()

		svc, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("user data error", func(t *testing.T) {
		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&generateCredentialReq{
			ID:         uuid.NewString(),
			Holder:     uuid.NewString(),
			VCSProfile: uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user data using id")
	})

	t.Run("invalid data", func(t *testing.T) {
		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		id := uuid.NewString()

		err = svc.store.Put(id, []byte("invalid-data"))
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&generateCredentialReq{
			ID:         id,
			Holder:     uuid.NewString(),
			VCSProfile: uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal user data")
	})

	t.Run("profile error", func(t *testing.T) {
		vcsRouter := mux.NewRouter()
		vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte(profileData))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(vcsRouter)

		defer vcs.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			VCSURL:        vcs.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		id := uuid.NewString()

		b, err := json.Marshal(searchData{
			UserData: map[string]interface{}{},
		})
		require.NoError(t, err)

		err = svc.store.Put(id, b)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&generateCredentialReq{
			ID:         id,
			Holder:     uuid.NewString(),
			VCSProfile: uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create credential")
	})

	t.Run("issue cred profile error", func(t *testing.T) {
		vcsRouter := mux.NewRouter()
		vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte(profileData))
			if err != nil {
				panic(err)
			}
		})
		vcsRouter.HandleFunc("/{id}/credentials/issue", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte(testCredentialRequest))
			if err != nil {
				panic(err)
			}
		})

		vcs := httptest.NewServer(vcsRouter)

		defer vcs.Close()

		cfg := &Config{
			StoreProvider: memstore.NewProvider(),
			VCSURL:        vcs.URL,
		}

		svc, err := New(cfg)
		require.NoError(t, err)

		id := uuid.NewString()

		b, err := json.Marshal(searchData{
			UserData: map[string]interface{}{},
		})
		require.NoError(t, err)

		err = svc.store.Put(id, b)
		require.NoError(t, err)

		reqBytes, err := json.Marshal(&generateCredentialReq{
			ID:         id,
			Holder:     uuid.NewString(),
			VCSProfile: uuid.NewString(),
		})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, generateCredentialPath, bytes.NewReader(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign credential")
	})
}
