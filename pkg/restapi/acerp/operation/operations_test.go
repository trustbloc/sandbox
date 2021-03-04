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
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	compclientops "github.com/trustbloc/edge-service/pkg/client/comparator/client/operations"
	compmodel "github.com/trustbloc/edge-service/pkg/client/comparator/models"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

const (
	sampleUserName   = "john.smith@example.com"
	samplePassword   = "pa$$word"
	sampleNationalID = "555341212"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}, ComparatorURL: "http://comp.example.com"})
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 17, len(svc.GetRESTHandlers()))
	})

	t.Run("error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStore: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ace-rp store provider : store open error")
		require.Nil(t, svc)
	})

	t.Run("empty comparator url", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "comparator url mandatory")
		require.Nil(t, svc)
	})
}

// nolint: bodyclose
func TestRegister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			DashboardHTML: file.Name(),
			RequestTokens: map[string]string{vcsIssuerRequestTokenName: "test"},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, nil),
		}
		svc.vClient = &mockVaultClient{}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("user exists", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		storeToReturnFromMockProvider, err := mem.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(sampleUserName, []byte(password))
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: storeToReturnFromMockProvider,
			},
			HomePageHTML:  file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("save user data error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("save error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, nil),
		}
		svc.vClient = &mockVaultClient{}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to save user data")
	})

	t.Run("parse form error", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			DashboardHTML: file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.register(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to parse form data")
	})

	t.Run("html error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, nil),
		}
		svc.vClient = &mockVaultClient{}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("create vault error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusInternalServerError, Body: ioutil.NopCloser(strings.NewReader("vault error")),
			},
		}
		svc.vClient = &mockVaultClient{CreateVaultErr: errors.New("vault error")}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to store national id in vault  - err:create vault")
	})

	t.Run("missing national id", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			DashboardHTML: file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, nil),
		}
		svc.vClient = &mockVaultClient{}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "nationalID is mandatory")
	})

	t.Run("failed to create vc", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			DashboardHTML: file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, &mockHTTPResponseData{status: http.StatusInternalServerError}, nil),
		}
		svc.vClient = &mockVaultClient{}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create vc")
	})

	t.Run("failed to save doc", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			RequestTokens: map[string]string{vcsIssuerRequestTokenName: "test"},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, nil),
		}
		svc.vClient = &mockVaultClient{SaveDocErr: errors.New("save error")}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save doc")
	})
}

func TestLogin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		storeToReturnFromMockProvider, err := mem.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider},
			DashboardHTML: file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string), URL: &url.URL{}}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("success for linking mode", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		storeToReturnFromMockProvider, err := mem.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider},
			ConsentHTML:   file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{
			Form: make(map[string][]string), Header: make(map[string][]string),
			URL: &url.URL{RawQuery: "action=link&id=1234"},
		}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("parse form error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.login(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to parse form data")
	})

	t.Run("invalid username", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
			HomePageHTML:  file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("invalid data in db", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleUserName] = []byte("invalid-json-data")

		storeToReturnFromMockProvider, err := mem.NewProvider().OpenStore("mockstoretoreturn")
		require.NoError(t, err)

		err = storeToReturnFromMockProvider.Put(sampleUserName, []byte("invalid-json-data"))
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: storeToReturnFromMockProvider},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, sampleUserName)

		svc.login(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unmarshal user data")
	})

	t.Run("db error", func(t *testing.T) {
		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{OpenStoreReturn: &mockstorage.Store{
				GetReturn: uDataBytes,
				ErrPut:    errors.New("db error"),
			}},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string), URL: &url.URL{}}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save session")
	})
}

func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			HomePageHTML:  file.Name(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{}

		svc.logout(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestConnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		profileID := uuid.New().String()

		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: profileID,
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		dBytes, err := json.Marshal(&profileData{})
		require.NoError(t, err)

		userStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = userStore.Put(profileID, dBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/connect?userName="+sampleUserName, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.connect(rr, req)
		require.Equal(t, http.StatusFound, rr.Code)

		ep, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)

		require.Equal(t, ep.Path, "/link")
		require.Equal(t, ep.Query().Get("callback"), svc.hostExternalURL+"/callback")
		require.NotEmpty(t, ep.Query().Get("state"))
	})

	t.Run("no username", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/connect", nil)
		require.NoError(t, err)

		svc.connect(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing username")
	})

	t.Run("data error", func(t *testing.T) {
		profileID := uuid.New().String()

		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: profileID,
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("GET", "/connect?userName="+sampleUserName, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.connect(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get profile data")

		userStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = userStore.Put(profileID, []byte("invalid-json"))
		require.NoError(t, err)

		rr = httptest.NewRecorder()

		svc.connect(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unamrshal profile data")
	})
}

func TestAccountLink(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
			LoginHTML:          file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		cID := uuid.New().String()
		cIDBytes, err := json.Marshal(&clientData{})
		require.NoError(t, err)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(cID, cIDBytes)
		require.NoError(t, err)

		state := uuid.New().String()
		endpoint := fmt.Sprintf(accountLinkURLFormat, svc.accountLinkProfile, cID, svc.hostExternalURL, state)

		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.link(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("no clientID", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "", nil)
		require.NoError(t, err)

		svc.link(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing client_id")
	})

	t.Run("no callback url", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", svc.accountLinkProfile+"/link?client_id="+uuid.New().String(), nil)
		require.NoError(t, err)

		svc.link(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing callback url")
	})

	t.Run("no state", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			AccountLinkProfile: "http://third-party-svc",
			HostExternalURL:    "http://my-external",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET",
			svc.accountLinkProfile+"/link?callback="+svc.hostExternalURL+"&client_id="+uuid.New().String(), nil)
		require.NoError(t, err)

		svc.link(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing state")
	})

	t.Run("client not found", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		state := uuid.New().String()
		endpoint := fmt.Sprintf(accountLinkURLFormat, svc.accountLinkProfile, uuid.New().String(), svc.hostExternalURL, state)

		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.link(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "get client data")
	})

	t.Run("invalid client data", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("store error")},
			},
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		state := uuid.New().String()
		endpoint := fmt.Sprintf(accountLinkURLFormat, svc.accountLinkProfile, uuid.New().String(), svc.hostExternalURL, state)

		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.link(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "unmarshal client data")
	})

	t.Run("store error", func(t *testing.T) {
		cIDBytes, err := json.Marshal(&clientData{})
		require.NoError(t, err)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{GetReturn: cIDBytes, ErrPut: errors.New("store error")},
			},
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		state := uuid.New().String()
		endpoint := fmt.Sprintf(accountLinkURLFormat, svc.accountLinkProfile, uuid.New().String(), svc.hostExternalURL, state)

		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.link(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save session data")
	})
}

func TestConsent(t *testing.T) {
	queryFmt := "?id=%s&sessionid=%s"

	t.Run("success", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{}

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		sessionid := uuid.New().String()

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		data := &sessionData{
			State:       uuid.New().String(),
			CallbackURL: "https://url/callback",
		}
		b, err = json.Marshal(data)
		require.NoError(t, err)

		stateID := uuid.New().String()
		err = txnStore.Put(stateID, b)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusFound, rr.Code)

		ep, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)

		require.Equal(t, "/callback", ep.Path)
		require.Equal(t, data.State, ep.Query().Get("state"))
		require.NotEmpty(t, ep.Query().Get("auth"))
	})

	t.Run("missing session query param", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, "", ""), nil)
		require.NoError(t, err)

		svc.consent(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "sessionid or id can't be empty")
	})

	t.Run("sessionid not found", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider:      mem.NewProvider(),
			AccountLinkProfile: "http://third-party-svc",
			HostExternalURL:    "http://my-external",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, uuid.NewString(), uuid.NewString()), nil)
		require.NoError(t, err)

		svc.consent(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get session data")
	})

	t.Run("stateID not found", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			AccountLinkProfile: "http://third-party-svc",
			HostExternalURL:    "http://my-external",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		sessionid := uuid.New().String()

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, uuid.NewString(), sessionid), nil)
		require.NoError(t, err)

		svc.consent(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get state data")
	})

	t.Run("no data for the user", func(t *testing.T) {
		memProvider := mem.NewProvider()
		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		sessionid := uuid.New().String()

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, uuid.NewString(), sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user data")
	})

	t.Run("invalid state data", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		sessionid := uuid.New().String()
		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		stateID := uuid.New().String()

		err = txnStore.Put(stateID, []byte("invalid data"))
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal state data")
	})

	t.Run("comparator config error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{GetConfigErr: errors.New("config error")}

		sessionid := uuid.New().String()
		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		data := &sessionData{
			State:       uuid.New().String(),
			CallbackURL: "https://url/callback",
		}

		b, err = json.Marshal(data)
		require.NoError(t, err)

		stateID := uuid.New().String()

		err = txnStore.Put(stateID, b)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed get config from comparator")

		svc.compClient = &mockComparatorClient{GetConfigResp: &compclientops.GetConfigOK{}}

		rr = httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "empty config from comparator")
	})

	t.Run("vault create auth error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{CreateAuthorizationErr: errors.New("vault auth error")}
		svc.compClient = &mockComparatorClient{}

		sessionid := uuid.New().String()
		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		data := &sessionData{
			State:       uuid.New().String(),
			CallbackURL: "https://url/callback",
		}

		b, err = json.Marshal(data)
		require.NoError(t, err)

		stateID := uuid.New().String()

		err = txnStore.Put(stateID, b)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "create vault authorization ")
	})

	t.Run("no auth token", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{CreateAuthorizationResp: &vault.CreatedAuthorization{}}
		svc.compClient = &mockComparatorClient{}

		sessionid := uuid.New().String()
		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		data := &sessionData{
			State:       uuid.New().String(),
			CallbackURL: "https://url/callback",
		}

		b, err = json.Marshal(data)
		require.NoError(t, err)

		stateID := uuid.New().String()

		err = txnStore.Put(stateID, b)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "missing auth token from vault-server")
	})

	t.Run("comparator auth failures", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:      memProvider,
			HostExternalURL:    "http://my-external",
			AccountLinkProfile: "http://third-party-svc",
			ComparatorURL:      "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{PostAuthorizationsErr: errors.New("http error")}

		sessionid := uuid.New().String()
		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(sessionid, []byte(sampleUserName))
		require.NoError(t, err)

		b, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, b)
		require.NoError(t, err)

		data := &sessionData{
			State:       uuid.New().String(),
			CallbackURL: "https://url/callback",
		}

		b, err = json.Marshal(data)
		require.NoError(t, err)

		stateID := uuid.New().String()

		err = txnStore.Put(stateID, b)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(queryFmt, stateID, sessionid), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "create comparator authorization")

		svc.compClient = &mockComparatorClient{PostAuthorizationsResp: &compclientops.PostAuthorizationsOK{}}

		svc.consent(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "missing auth token from comparator")
	})
}

func TestAccountLinkCallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:     memProvider,
			AccountLinkedHTML: file.Name(),
			ComparatorURL:     "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{}

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		state := uuid.New().String()

		err = txnStore.Put(state, []byte(sampleUserName))
		require.NoError(t, err)

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String()+"&state="+state, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("missing auth", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/callback", nil)
		require.NoError(t, err)

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing authorization")
	})

	t.Run("missing state", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String(), nil)
		require.NoError(t, err)

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing state")
	})

	t.Run("db error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		state := uuid.New().String()

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String()+"&state="+state, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get state")

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(state, []byte(sampleUserName))
		require.NoError(t, err)

		rr = httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to get user data")
	})

	t.Run("vault server error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{CreateAuthorizationErr: errors.New("create auth error")}
		svc.compClient = &mockComparatorClient{}

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		state := uuid.New().String()

		err = txnStore.Put(state, []byte(sampleUserName))
		require.NoError(t, err)

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String()+"&state="+state, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create vault authorization")

		svc.vClient = &mockVaultClient{CreateAuthorizationResp: &vault.CreatedAuthorization{}}

		rr = httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "missing auth token from vault-server")
	})

	t.Run("comparator - get error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{GetConfigErr: errors.New("config error")}

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		state := uuid.New().String()

		err = txnStore.Put(state, []byte(sampleUserName))
		require.NoError(t, err)

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String()+"&state="+state, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed get config from comparator")

		svc.compClient = &mockComparatorClient{GetConfigResp: &compclientops.GetConfigOK{}}

		rr = httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "empty config from comparator")
	})

	t.Run("comparator - compare error", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{PostCompareErr: errors.New("compare error")}

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		state := uuid.New().String()

		err = txnStore.Put(state, []byte(sampleUserName))
		require.NoError(t, err)

		uDataBytes, err := json.Marshal(&userData{})
		require.NoError(t, err)

		err = txnStore.Put(sampleUserName, uDataBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "/callback?auth="+uuid.New().String()+"&state="+state, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to compare docs")

		svc.compClient = &mockComparatorClient{PostCompareResp: &compclientops.PostCompareOK{}}

		rr = httptest.NewRecorder()

		svc.accountLinkCallback(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "missing compare result from comparator")
	})
}

func TestCreateClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		cReq := clientReq{
			DID:      "did:example:123",
			Callback: "http://test/callback",
		}

		reqBytes, err := json.Marshal(cReq)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createClient(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)

		var resp *clientResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.NotEmpty(t, resp.ClientID)
		require.NotEmpty(t, resp.ClientSecret)
		require.Equal(t, cReq.DID, resp.DID)
		require.Equal(t, cReq.Callback, resp.Callback)
	})

	t.Run("invalid request", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("POST", client, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createClient(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("save error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		reqBytes, err := json.Marshal(clientReq{})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createClient(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save client data")
	})
}

func TestGetCreate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		id := uuid.New().String()

		cReq := clientData{
			ClientID: id,
			DID:      "did:example:123",
			Callback: "http://test/callback",
		}

		reqBytes, err := json.Marshal(cReq)
		require.NoError(t, err)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(id, reqBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", client+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getClient(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *clientData

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.NotEmpty(t, resp.ClientID)
		require.Equal(t, cReq.DID, resp.DID)
		require.Equal(t, cReq.Callback, resp.Callback)
	})

	t.Run("no data for the id", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("GET", client+"/"+uuid.New().String(), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getClient(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get data")
	})

	t.Run("invalid data for the id", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		id := uuid.New().String()

		err = txnStore.Put(id, []byte("invalid-json"))
		require.NoError(t, err)

		req, err := http.NewRequest("GET", client+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getClient(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal data")
	})
}

func TestCreateProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		cReq := profileData{
			ID:       uuid.New().String(),
			DID:      "did:example:123",
			Callback: "http://test/callback",
		}

		reqBytes, err := json.Marshal(cReq)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createProfile(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)

		var resp *profileData

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.Equal(t, cReq.ID, resp.ID)
		require.Equal(t, cReq.ClientID, resp.ClientID)
		require.Equal(t, cReq.ClientSecret, resp.ClientSecret)
		require.Equal(t, cReq.DID, resp.DID)
		require.Equal(t, cReq.Callback, resp.Callback)
	})

	t.Run("invalid request", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("POST", client, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createProfile(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("save error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		reqBytes, err := json.Marshal(profileData{})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.createProfile(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save client data")
	})
}

func TestGetProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		id := uuid.New().String()

		cReq := profileData{
			ClientID: id,
			DID:      "did:example:123",
			Callback: "http://test/callback",
		}

		reqBytes, err := json.Marshal(cReq)
		require.NoError(t, err)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(id, reqBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", profile+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getProfile(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *clientData

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.NotEmpty(t, resp.ClientID)
		require.Equal(t, cReq.DID, resp.DID)
		require.Equal(t, cReq.Callback, resp.Callback)
	})

	t.Run("no data for the id", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("GET", client+"/"+uuid.New().String(), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getProfile(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get data")
	})

	t.Run("invalid data for the id", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		id := uuid.New().String()

		err = txnStore.Put(id, []byte("invalid-json"))
		require.NoError(t, err)

		req, err := http.NewRequest("GET", client+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getProfile(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal data")
	})
}

func TestDeleteProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		memProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider: memProvider,
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		id := uuid.New().String()

		cReq := profileData{
			ClientID: id,
		}

		reqBytes, err := json.Marshal(cReq)
		require.NoError(t, err)

		txnStore, err := memProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(id, reqBytes)
		require.NoError(t, err)

		req, err := http.NewRequest("DELETE", profile+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.deleteProfile(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrDelete: errors.New("delete error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("DELETE", client+"/"+uuid.New().String(), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.deleteProfile(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to delete data")
	})
}

func TestGetUsers(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		userStore, err := mem.NewProvider().OpenStore("userstore")
		require.NoError(t, err)

		svc.userStore = userStore

		uData := userData{
			ID:              uuid.NewString(),
			UserName:        sampleUserName,
			VaultID:         uuid.NewString(),
			NationalIDDocID: uuid.NewString(),
		}

		uBytes, err := json.Marshal(uData)
		require.NoError(t, err)

		err = svc.store.Put(uData.UserName, uBytes)
		require.NoError(t, err)

		uMap := userIDNameMap{
			ID:          uData.ID,
			UserName:    uData.UserName,
			CreatedTime: util.NewTime(time.Now()),
		}

		uBytes, err = json.Marshal(uMap)
		require.NoError(t, err)

		err = userStore.Put(uData.ID, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest("GET", users, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUsers(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *getUserDataResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Users))
	})

	t.Run("get only 5 records", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		userStore, err := mem.NewProvider().OpenStore("userstore")
		require.NoError(t, err)

		svc.userStore = userStore

		for i := 0; i < 10; i++ {
			reqData := userData{
				ID:              uuid.NewString(),
				UserName:        sampleUserName,
				VaultID:         uuid.NewString(),
				NationalIDDocID: uuid.NewString(),
			}

			reqBytes, mErr := json.Marshal(reqData)
			require.NoError(t, mErr)

			err = svc.store.Put(reqData.UserName, reqBytes)
			require.NoError(t, err)

			uMap := userIDNameMap{
				ID:          reqData.ID,
				UserName:    reqData.UserName,
				CreatedTime: util.NewTime(time.Now()),
			}

			reqBytes, err = json.Marshal(uMap)
			require.NoError(t, err)

			err = userStore.Put(reqData.ID, reqBytes, storage.Tag{Name: userTagName})
			require.NoError(t, err)
		}

		req, err := http.NewRequest("GET", users, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUsers(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *getUserDataResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 5, len(resp.Users))
	})
}

// nolint: bodyclose
func TestCreateAuthorizations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cID := uuid.New().String()

		svcMemProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:    svcMemProvider,
			ComparatorURL:    "http://comp.example.com",
			ExtractorProfile: cID,
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{}
		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, &mockHTTPResponseData{status: http.StatusOK}),
		}

		userStore, err := mem.NewProvider().OpenStore("userstore")
		require.NoError(t, err)

		svc.userStore = userStore

		uData := userData{
			ID:              uuid.NewString(),
			UserName:        sampleUserName,
			VaultID:         uuid.NewString(),
			NationalIDDocID: uuid.NewString(),
		}

		uBytes, err := json.Marshal(uData)
		require.NoError(t, err)

		txnStore, err := svcMemProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(uData.UserName, uBytes)
		require.NoError(t, err)

		err = userStore.Put(uData.ID, []byte(uData.UserName), storage.Tag{Name: userTagName})
		require.NoError(t, err)

		uMap := userIDNameMap{
			ID:          uData.ID,
			UserName:    uData.UserName,
			CreatedTime: util.NewTime(time.Now()),
		}

		uBytes, err = json.Marshal(uMap)
		require.NoError(t, err)

		err = userStore.Put(uData.ID, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		cIDBytes, err := json.Marshal(&clientData{})
		require.NoError(t, err)

		err = txnStore.Put(cID, cIDBytes)
		require.NoError(t, err)

		uBytes, err = json.Marshal(generateUserAuthReq{Users: []string{uData.ID}})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, userAuth, bytes.NewReader(uBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateUserAuths(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *userAuthData

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.UserAuths))
	})

	t.Run("invalid client id", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		uBytes, err := json.Marshal(generateUserAuthReq{})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, userAuth, bytes.NewReader(uBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateUserAuths(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get profile data")
	})

	t.Run("comparator and vault error", func(t *testing.T) {
		cID := uuid.New().String()

		svcMemProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:    svcMemProvider,
			ComparatorURL:    "http://comp.example.com",
			ExtractorProfile: cID,
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{CreateAuthorizationErr: errors.New("vault error")}
		svc.compClient = &mockComparatorClient{}

		userStore, err := mem.NewProvider().OpenStore("userstore")
		require.NoError(t, err)

		svc.userStore = userStore

		uData := userData{
			ID:              uuid.NewString(),
			UserName:        sampleUserName,
			VaultID:         uuid.NewString(),
			NationalIDDocID: uuid.NewString(),
		}

		uBytes, err := json.Marshal(uData)
		require.NoError(t, err)

		txnStore, err := svcMemProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(uData.UserName, uBytes)
		require.NoError(t, err)

		uMap := userIDNameMap{
			ID:          uData.ID,
			UserName:    uData.UserName,
			CreatedTime: util.NewTime(time.Now()),
		}

		uBytes, err = json.Marshal(uMap)
		require.NoError(t, err)

		err = userStore.Put(uData.ID, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		cIDBytes, err := json.Marshal(&clientData{})
		require.NoError(t, err)

		err = txnStore.Put(cID, cIDBytes)
		require.NoError(t, err)

		uBytes, err = json.Marshal(generateUserAuthReq{})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, userAuth, bytes.NewReader(uBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateUserAuths(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed create authorization")

		svc.compClient = &mockComparatorClient{GetConfigErr: errors.New("config error")}

		req, err = http.NewRequest(http.MethodPost, userAuth, bytes.NewReader(uBytes))
		require.NoError(t, err)

		rr = httptest.NewRecorder()

		svc.generateUserAuths(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed get config from comparator")
	})

	t.Run("user/auth rest call error", func(t *testing.T) {
		cID := uuid.New().String()

		svcMemProvider := mem.NewProvider()

		svc, err := New(&Config{
			StoreProvider:    svcMemProvider,
			ComparatorURL:    "http://comp.example.com",
			ExtractorProfile: cID,
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.vClient = &mockVaultClient{}
		svc.compClient = &mockComparatorClient{}
		svc.httpClient = &mockHTTPClient{
			doFunc: mockHTTPResponse(t, nil, &mockHTTPResponseData{status: http.StatusInternalServerError}),
		}

		userStore, err := mem.NewProvider().OpenStore("userstore")
		require.NoError(t, err)

		svc.userStore = userStore

		uData := userData{
			ID:              uuid.NewString(),
			UserName:        sampleUserName,
			VaultID:         uuid.NewString(),
			NationalIDDocID: uuid.NewString(),
		}

		uBytes, err := json.Marshal(uData)
		require.NoError(t, err)

		txnStore, err := svcMemProvider.OpenStore(txnStoreName)
		require.NoError(t, err)

		err = txnStore.Put(uData.UserName, uBytes)
		require.NoError(t, err)

		uMap := userIDNameMap{
			ID:          uData.ID,
			UserName:    uData.UserName,
			CreatedTime: util.NewTime(time.Now()),
		}

		uBytes, err = json.Marshal(uMap)
		require.NoError(t, err)

		err = userStore.Put(uData.ID, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		cIDBytes, err := json.Marshal(&clientData{})
		require.NoError(t, err)

		err = txnStore.Put(cID, cIDBytes)
		require.NoError(t, err)

		uBytes, err = json.Marshal(generateUserAuthReq{})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, userAuth, bytes.NewReader(uBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.generateUserAuths(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user auth data")
	})
}

func TestSaveUserAuth(t *testing.T) {
	userAuths := make([]userAuthorization, 0)
	userAuths = append(userAuths, userAuthorization{
		Name:      sampleUserName,
		ID:        uuid.NewString(),
		AuthToken: "abc123",
	})

	reqBytes, err := json.Marshal(userAuthData{UserAuths: userAuths})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.saveUserAuths(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid request", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("POST", client, strings.NewReader("invalid-json"))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.saveUserAuths(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request")
	})

	t.Run("no auths in the request", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rBytes, err := json.Marshal(userAuthData{})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(rBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.saveUserAuths(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "no user auths in the request")
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrPut: errors.New("save error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest("POST", client, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.saveUserAuths(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to save user auth data")
	})
}

func TestExtractRequests(t *testing.T) {
	uData := userAuthData{
		Source:        "test",
		SubmittedTime: util.NewTime(time.Now()),
		UserAuths: []userAuthorization{
			{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
			{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
		},
	}

	uBytes, err := json.Marshal(uData)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{}

		err = svc.userAuthStore.Put(uuid.NewString(), uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, userExtract, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.extractRequests(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *extractResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.ExtractData))
	})

	t.Run("get only 5 records", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{}

		for i := 0; i < 10; i++ {
			reqBytes, mErr := json.Marshal(userAuthData{
				Source:        "test" + fmt.Sprint(i),
				SubmittedTime: util.NewTime(time.Now()),
				UserAuths: []userAuthorization{
					{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
					{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
				},
			})
			require.NoError(t, mErr)

			err = svc.userAuthStore.Put(uuid.NewString(), reqBytes, storage.Tag{Name: userTagName})
			require.NoError(t, err)
		}

		req, err := http.NewRequest(http.MethodGet, userExtract, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.extractRequests(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *extractResp

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 5, len(resp.ExtractData))
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrQuery: errors.New("query error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest(http.MethodGet, userExtract, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.extractRequests(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user auth data: get all user auth data")
	})

	t.Run("invalid data in the db", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		err = svc.userAuthStore.Put(uuid.NewString(), []byte("invalid-data"), storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, userExtract, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.extractRequests(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user auth data: unamrshal user auth data invalid-data")
	})
}

func TestGetUserExtract(t *testing.T) {
	uData := userAuthData{
		Source:        "test",
		SubmittedTime: util.NewTime(time.Now()),
		UserAuths: []userAuthorization{
			{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
			{ID: uuid.NewString(), Name: sampleUserName, AuthToken: uuid.NewString()},
		},
	}

	uBytes, err := json.Marshal(uData)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{}

		id := uuid.NewString()

		err = svc.userAuthStore.Put(id, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, userExtract+"/"+id, nil)
		require.NoError(t, err)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var resp *getExtractData

		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, 2, len(resp.Data))
	})

	t.Run("db error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				OpenStoreReturn: &mockstorage.Store{ErrGet: errors.New("get error")},
			},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		req, err := http.NewRequest(http.MethodGet, userExtract+"/"+uuid.NewString(), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get user auth data")
	})

	t.Run("invalid data in the db", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		id := uuid.NewString()

		err = svc.userAuthStore.Put(id, []byte("invalid-data"), storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, userExtract+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal user auth data")
	})

	t.Run("extract api error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: mem.NewProvider(),
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.compClient = &mockComparatorClient{PostExtractErr: errors.New("extract api error")}

		id := uuid.NewString()

		err = svc.userAuthStore.Put(id, uBytes, storage.Tag{Name: userTagName})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, userExtract+"/"+id, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to extract data")

		svc.compClient = &mockComparatorClient{PostExtractResp: &compclientops.PostExtractOK{Payload: &compmodel.ExtractResp{
			Documents: []*compmodel.ExtractRespDocumentsItems0{},
		}}}

		rr = httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "count of documents 0 doesnt match the expected 2")

		svc.compClient = &mockComparatorClient{PostExtractResp: &compclientops.PostExtractOK{Payload: &compmodel.ExtractResp{
			Documents: []*compmodel.ExtractRespDocumentsItems0{
				{ID: uuid.NewString(), Contents: 1256},
				{ID: uuid.NewString(), Contents: "1256"},
			},
		}}}

		rr = httptest.NewRecorder()

		svc.getUserExtract(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid content; expected string type")
	})
}

type mockHTTPClient struct {
	respValue *http.Response
	respErr   error
	doFunc    func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.respErr != nil {
		return nil, m.respErr
	}

	if m.doFunc != nil {
		return m.doFunc(req)
	}

	return m.respValue, nil
}

func mockHTTPResponse(t *testing.T, vcResp,
	authResp *mockHTTPResponseData) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		status := http.StatusCreated
		respByes := []byte("")

		var err error

		switch req.URL.Path {
		case "/credentials/issueCredential":
			cred := verifiable.Credential{}
			cred.ID = uuid.New().URN()
			cred.Context = []string{credentialContext}
			cred.Types = []string{"VerifiableCredential"}
			// issuerID will be overwritten in the issuer
			cred.Issuer = verifiable.Issuer{ID: uuid.New().URN()}
			cred.Issued = util.NewTime(time.Now().UTC())

			credentialSubject := make(map[string]interface{})
			credentialSubject["id"] = uuid.New().URN()
			cred.Subject = credentialSubject

			respByes, err = cred.MarshalJSON()
			require.NoError(t, err)

			if vcResp != nil {
				status = vcResp.status
			}
		case "/users/auth":
			status = http.StatusOK
			respByes, err = json.Marshal(
				userAuthData{UserAuths: []userAuthorization{{AuthToken: uuid.New().String()}}},
			)
			require.NoError(t, err)

			if authResp != nil {
				status = authResp.status
				respByes = authResp.respByes
			}
		}

		resp := &http.Response{
			StatusCode: status,
			Body:       ioutil.NopCloser(bytes.NewReader(respByes)),
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				logger.Warnf("failed to close response body")
			}
		}()

		return resp, nil
	}
}

type mockHTTPResponseData struct {
	status   int
	respByes []byte
}

type mockVaultClient struct {
	CreateVaultErr          error
	SaveDocErr              error
	CreateAuthorizationErr  error
	CreateAuthorizationResp *vault.CreatedAuthorization
}

func (m *mockVaultClient) CreateVault() (*vault.CreatedVault, error) {
	if m.CreateVaultErr != nil {
		return nil, m.CreateVaultErr
	}

	return &vault.CreatedVault{
		ID: "did:key:123",
	}, nil
}

func (m *mockVaultClient) SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error) {
	if m.SaveDocErr != nil {
		return nil, m.SaveDocErr
	}

	return nil, nil
}

func (m *mockVaultClient) CreateAuthorization(vaultID, requestingParty string,
	scope *vault.AuthorizationsScope) (*vault.CreatedAuthorization, error) {
	if m.CreateAuthorizationErr != nil {
		return nil, m.CreateAuthorizationErr
	}

	if m.CreateAuthorizationResp != nil {
		return m.CreateAuthorizationResp, nil
	}

	return &vault.CreatedAuthorization{Tokens: &vault.Tokens{EDV: uuid.New().String(), KMS: uuid.New().String()}}, nil
}

type mockComparatorClient struct {
	GetConfigErr           error
	GetConfigResp          *compclientops.GetConfigOK
	PostAuthorizationsErr  error
	PostAuthorizationsResp *compclientops.PostAuthorizationsOK
	PostCompareErr         error
	PostCompareResp        *compclientops.PostCompareOK
	PostExtractErr         error
	PostExtractResp        *compclientops.PostExtractOK
}

func (m *mockComparatorClient) GetConfig(params *compclientops.GetConfigParams) (*compclientops.GetConfigOK, error) {
	if m.GetConfigErr != nil {
		return nil, m.GetConfigErr
	}

	if m.GetConfigResp != nil {
		return m.GetConfigResp, nil
	}

	did := "did:example:789"

	return &compclientops.GetConfigOK{
		Payload: &compmodel.Config{AuthKeyURL: "did:example:123#xyz", Did: &did},
	}, nil
}

func (m *mockComparatorClient) PostAuthorizations(
	params *compclientops.PostAuthorizationsParams) (*compclientops.PostAuthorizationsOK, error) {
	if m.PostAuthorizationsErr != nil {
		return nil, m.PostAuthorizationsErr
	}

	if m.PostAuthorizationsResp != nil {
		return m.PostAuthorizationsResp, nil
	}

	return &compclientops.PostAuthorizationsOK{Payload: &compmodel.Authorization{AuthToken: uuid.New().String()}}, nil
}

func (m *mockComparatorClient) PostCompare(
	params *compclientops.PostCompareParams) (*compclientops.PostCompareOK, error) {
	if m.PostCompareErr != nil {
		return nil, m.PostCompareErr
	}

	if m.PostCompareResp != nil {
		return m.PostCompareResp, nil
	}

	return &compclientops.PostCompareOK{Payload: &compmodel.ComparisonResult{Result: true}}, nil
}

func (m *mockComparatorClient) PostExtract(
	params *compclientops.PostExtractParams) (*compclientops.PostExtractOK, error) {
	if m.PostExtractErr != nil {
		return nil, m.PostExtractErr
	}

	if m.PostExtractResp != nil {
		return m.PostExtractResp, nil
	}

	respDoc := make([]*compmodel.ExtractRespDocumentsItems0, 0)
	for _, v := range params.Extract.Queries() {
		respDoc = append(respDoc, &compmodel.ExtractRespDocumentsItems0{
			ID:       v.ID(),
			Contents: uuid.NewString(),
		})
	}

	return &compclientops.PostExtractOK{Payload: &compmodel.ExtractResp{
		Documents: respDoc,
	}}, nil
}
