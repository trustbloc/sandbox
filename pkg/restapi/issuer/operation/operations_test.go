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

	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/token"
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

const holder = "did:example.com"
const domain = "issuer.interop.transmute.world"
const challenge = "3970cad8-14ff-4ac1-ada9-0995c862df2e"
const authResp = `{
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

func TestController_New(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		op, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("test new - error", func(t *testing.T) {
		// create error
		op, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("store create error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer store provider : store create error")
		require.Nil(t, op)

		op, err = New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStoreHandle: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer store provider : store open error")
		require.Nil(t, op)
	})
}

func TestOperation_Login(t *testing.T) {
	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{}}
	handler := getHandlerWithConfig(t, login, cfg)

	buff, status, err := handleRequest(handler, nil, login, true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "vcs profile is empty")
	require.Equal(t, http.StatusBadRequest, status)

	buff, status, err = handleRequest(handler, nil,
		login+"?didCommScope=CrediCardStatement&demoType=DIDComm", true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "adapterProfile profile is empty")
	require.Equal(t, http.StatusBadRequest, status)

	buff, status, err = handleRequest(handler, nil,
		login+"?didCommScope=CrediCardStatement&demoType=DIDComm&adapterProfile=adapter-123", true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)

	buff, status, err = handleRequest(handler, nil, login+"?scope=test&vcsProfile=vc-issuer-1", true)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_Login3(t *testing.T) {
	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{}}
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

func TestOperation_Callback(t *testing.T) { // nolint: gocognit
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	t.Run("test callback - non didcomm", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
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

		cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			DIDAuthHTML:   file.Name(),
			StoreProvider: &mockstorage.Provider{}}
		handler := getHandlerWithConfig(t, callback, cfg)

		_, status, err := handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		// test ledger cookie not found
		cfg = &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(), DIDAuthHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{}}
		handler = getHandlerWithConfig(t, callback, cfg)

		body, status, err := handleRequest(handler, headers, callback, false)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "failed to get cookie")

		// test html not exist
		cfg = &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: "",
			StoreProvider: &mockstorage.Provider{}}
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

		cfg = &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: httptest.NewServer(r).URL, ReceiveVCHTML: file.Name(),
			DIDAuthHTML:   file.Name(),
			StoreProvider: &mockstorage.Provider{}}
		handler = getHandlerWithConfig(t, callback, cfg)

		fmt.Println("here here 1")
		body, status, err = handleRequest(handler, headers, callback, true)
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, status)
		require.Contains(t, body.String(), "failed to create credential: retrieve profile")
	})

	t.Run("test callback - didcomm", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
		}))
		defer cms.Close()

		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		t.Run("test callback didcomm - success", func(t *testing.T) {
			vcsRouter := mux.NewRouter()
			vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
				_, err := writer.Write([]byte(profileData))
				if err != nil {
					panic(err)
				}
			})
			vcsRouter.HandleFunc("/{id}/credentials/issueCredential", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusCreated)
				_, err := writer.Write([]byte(testCredentialRequest))
				if err != nil {
					panic(err)
				}
			})

			vcs := httptest.NewServer(vcsRouter)

			defer vcs.Close()

			cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
				CMSURL:        cms.URL,
				VCSURL:        vcs.URL,
				DIDCommHTML:   file.Name(),
				StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}}}
			handler := getHandlerWithConfig(t, callback, cfg)

			_, status, err := handleRequestWithCookies(handler, headers, callback,
				[]*http.Cookie{{Name: vcsProfileCookie, Value: "vc-1"}, {Name: demoTypeCookie, Value: didCommDemo},
					{Name: adapterProfileCookie, Value: "adapter-123"}})
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, status)
		})

		t.Run("test callback didcomm - success", func(t *testing.T) {
			vcsRouter := mux.NewRouter()
			vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
				_, err := writer.Write([]byte(profileData))
				if err != nil {
					panic(err)
				}
			})

			vcs := httptest.NewServer(vcsRouter)

			cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
				CMSURL:        cms.URL,
				VCSURL:        vcs.URL,
				StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
			}
			handler := getHandlerWithConfig(t, callback, cfg)

			respData, status, err := handleRequestWithCookies(handler, headers, callback,
				[]*http.Cookie{{Name: vcsProfileCookie, Value: "vc-1"}, {Name: demoTypeCookie, Value: didCommDemo}})
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, status)
			require.Contains(t, respData.String(), "failed to get adapterProfileCookie")
		})

		t.Run("test callback didcomm - store error", func(t *testing.T) {
			vcsRouter := mux.NewRouter()
			vcsRouter.HandleFunc("/profile/{id}", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
				_, err := writer.Write([]byte(profileData))
				if err != nil {
					panic(err)
				}
			})
			vcsRouter.HandleFunc("/{id}/credentials/issueCredential", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusCreated)
				_, err := writer.Write([]byte(testCredentialRequest))
				if err != nil {
					panic(err)
				}
			})

			vcs := httptest.NewServer(vcsRouter)

			defer vcs.Close()

			cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
				CMSURL:      cms.URL,
				VCSURL:      vcs.URL,
				DIDCommHTML: file.Name(),
				StoreProvider: &mockstorage.Provider{
					Store: &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("save error")},
				},
			}
			handler := getHandlerWithConfig(t, callback, cfg)

			respData, status, err := handleRequestWithCookies(handler, headers, callback,
				[]*http.Cookie{{Name: vcsProfileCookie, Value: "vc-1"}, {Name: demoTypeCookie, Value: didCommDemo},
					{Name: adapterProfileCookie, Value: "adapter-123"}})
			require.NoError(t, err)
			require.Equal(t, http.StatusInternalServerError, status)
			require.Contains(t, respData.String(), "failed to store state subject mapping")
		})
	})
}

func TestOperation_GenerateVC(t *testing.T) {
	t.Run("generate VC success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "users") {
				fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.HandleFunc("/{id}/credentials/issueCredential", func(writer http.ResponseWriter, request *http.Request) {
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

		cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{}}

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
		req.Form.Add("challenge", challenge)
		svc.generateVC(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "DID Auth failed: embedded proof is missing")

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

	t.Run("generate VC - store error", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "users") {
				fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		})

		router.HandleFunc("/{id}/credentials/issueCredential", func(writer http.ResponseWriter, request *http.Request) {
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

		cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name(),
			StoreProvider: &mockstorage.Provider{}}

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
				fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
			} else {
				fmt.Fprintln(w, jsonArray)
			}
		}))
		defer cms.Close()

		router := mux.NewRouter()
		router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		router.HandleFunc("/{id}/credentials/issueCredential", func(writer http.ResponseWriter, request *http.Request) {
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

		cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			CMSURL: cms.URL, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{}}

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
		StoreProvider: &mockstorage.Provider{}})
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
		StoreProvider: &mockstorage.Provider{}})
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

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "cms",
		StoreProvider: &mockstorage.Provider{}}
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

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: cms.URL, VCSURL: "vcs",
		StoreProvider: &mockstorage.Provider{}}
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
		svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		err = svc.storeCredential([]byte(testCredentialRequest), "")
		require.NoError(t, err)
	})
	t.Run("store credential error invalid url ", func(t *testing.T) {
		svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			VCSURL:        "%%&^$",
			StoreProvider: &mockstorage.Provider{}})
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
		svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL,
			StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		err = svc.storeCredential([]byte(testCredentialRequest), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "201 Created")
	})
}

func TestOperation_GetCMSData_InvalidURL(t *testing.T) {
	svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "xyz:cms",
		StoreProvider: &mockstorage.Provider{}})
	require.NotNil(t, svc)
	require.NoError(t, err)

	data, err := svc.getCMSData(&oauth2.Token{}, &token.Introspection{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	require.Nil(t, data)
}

func TestOperation_GetCMSData_InvalidHTTPRequest(t *testing.T) {
	svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL:        "http://cms\\",
		StoreProvider: &mockstorage.Provider{}})
	require.NotNil(t, svc)
	require.NoError(t, err)

	data, err := svc.getCMSData(&oauth2.Token{}, &token.Introspection{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
	require.Nil(t, data)
}

func TestOperation_CreateCredential_Errors(t *testing.T) {
	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{}}

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
	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		StoreProvider: &mockstorage.Provider{}}

	t.Run("test success", func(t *testing.T) {
		cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, fmt.Sprintf("[%s]", foo))
		}))
		defer cms.Close()

		cfg.CMSURL = cms.URL
		svc, err := New(cfg)
		require.NotNil(t, svc)
		require.NoError(t, err)

		data, err := svc.getCMSData(&oauth2.Token{}, &token.Introspection{})
		require.NoError(t, err)
		require.Equal(t, data["email"], "foo@bar.com")
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

		data, err := svc.getCMSData(&oauth2.Token{}, &token.Introspection{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "user not found")
		require.Nil(t, data)
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
		data, err := unmarshalUser([]byte(fmt.Sprintf("[{},{}]")))
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
		data, err := unmarshalSubject([]byte(fmt.Sprintf("[{},{}]")))
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

func TestRevokeVC(t *testing.T) {
	t.Run("test error from parse form", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		svc.revokeVC(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse form")
	})

	t.Run("test error from create http request", func(t *testing.T) {
		svc, err := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			VCSURL:        "http://vcs\\",
			StoreProvider: &mockstorage.Provider{}})
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create new http request")
	})

	t.Run("test error from http post", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to update vc status")
	})

	t.Run("test vc html not exist", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc(vcsUpdateStatusEndpoint, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		svc, err := New(&Config{VCHTML: "", VCSURL: vcs.URL, StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.revokeVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		router := mux.NewRouter()
		router.HandleFunc(vcsUpdateStatusEndpoint, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
		})

		vcs := httptest.NewServer(router)

		defer vcs.Close()

		svc, err := New(&Config{VCHTML: file.Name(), VCSURL: vcs.URL, StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}

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

		s := make(map[string][]byte)
		s[state] = []byte(testCredentialRequest)

		ops.store = &mockstorage.MockStore{
			Store:  s,
			ErrPut: errors.New("error inserting data"),
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

	t.Run("test didcomm callback handler - state/token missing", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{DIDCommHTML: file.Name(), StoreProvider: &mockstorage.Provider{}}

		handler := getHandlerWithConfig(t, didcommCallback, cfg)

		respData, status, err := handleRequest(handler, headers,
			fmt.Sprintf(urlFmt, ""), false)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, respData.String(), "missing state in http query param")
	})

	t.Run("test didcomm callback handler - invalid token", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cfg := &Config{DIDCommHTML: file.Name(), StoreProvider: memstore.NewProvider()}

		handler := getHandlerWithConfig(t, didcommCallback, cfg)

		respData, status, err := handleRequest(handler, headers,
			fmt.Sprintf(urlFmt, uuid.New().String()), false)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, respData.String(), "failed to validate the adapter response: invalid state")
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
		s := make(map[string][]byte)
		cfg := &Config{StoreProvider: &mockstorage.Provider{
			Store: &mockstorage.MockStore{Store: s, ErrPut: errors.New("save error")},
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

		tkn := uuid.New().String()
		err := ops.store.Put(tkn, []byte(testCredentialRequest))
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommCredential, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, rr.Body.String(), testCredentialRequest)
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
		require.Contains(t, rr.Body.String(), "invalid token")
	})
}

func TestDIDCommAssuranceDataHandler(t *testing.T) {
	t.Run("test didcomm assurance data - success", func(t *testing.T) {
		cfg := &Config{StoreProvider: memstore.NewProvider()}

		ops, handler := getHandlerWithOps(t, didcommAssuranceData, cfg)

		tkn := uuid.New().String()
		err := ops.store.Put(tkn, []byte("data"))
		require.NoError(t, err)

		req := &adapterDataReq{
			Token: tkn,
		}

		reqBytes, jsonErr := json.Marshal(req)
		require.NoError(t, jsonErr)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, didcommAssuranceData, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, rr.Body.String(), assuranceData)
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
		require.Contains(t, rr.Body.String(), "invalid token")
	})
}

func handleRequest(handler Handler, headers map[string]string, path string, addCookie bool) (*bytes.Buffer, int, error) { //nolint:lll
	var cookie *http.Cookie

	if addCookie {
		cookie = &http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"}
	}

	return handleRequestWithCokie(handler, headers, path, cookie)
}

func handleRequestWithCokie(handler Handler, headers map[string]string, path string, cookie *http.Cookie) (*bytes.Buffer, int, error) { //nolint:lll
	req, err := http.NewRequest(handler.Method(), path, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, 0, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	if cookie != nil {
		req.AddCookie(cookie)
	}

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func handleRequestWithCookies(handler Handler, headers map[string]string, path string, cookies []*http.Cookie) (*bytes.Buffer, int, error) { //nolint:lll,unparam
	req, err := http.NewRequest(handler.Method(), path, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, 0, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func getHandlerWithOps(t *testing.T, lookup string, cfg *Config) (*Operation, Handler) {
	svc, err := New(cfg)
	require.NotNil(t, svc)
	require.NoError(t, err)

	return svc, handlerLookup(t, svc, lookup)
}

func getHandlerWithConfig(t *testing.T, lookup string, cfg *Config) Handler {
	svc, err := New(cfg)
	require.NotNil(t, svc)
	require.NoError(t, err)

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder { // nolint: unparam,lll
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, httpReq)

	return rr
}

type mockTokenIssuer struct {
	err error
}

func (m *mockTokenIssuer) AuthCodeURL(w http.ResponseWriter) string {
	return "url"
}

func (m *mockTokenIssuer) Exchange(r *http.Request) (*oauth2.Token, error) {
	if m.err != nil {
		return nil, m.err
	}

	return &oauth2.Token{}, nil
}

func (m *mockTokenIssuer) Client(t *oauth2.Token) *http.Client {
	return http.DefaultClient
}

type mockTokenResolver struct {
	err error
}

func (r *mockTokenResolver) Resolve(tk string) (*token.Introspection, error) {
	if r.err != nil {
		return nil, r.err
	}

	return &token.Introspection{}, nil
}
