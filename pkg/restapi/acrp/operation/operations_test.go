/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

const (
	sampleUserName   = "john.smith@example.com"
	samplePassword   = "pa$$word"
	sampleNationalID = "555341212"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 4, len(svc.GetRESTHandlers()))
	})

	t.Run("error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStoreHandle: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "acrp store provider : store open error")
		require.Nil(t, svc)
	})
}

func TestRegister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
			DashboardHTML: file.Name(),
			RequestTokens: map[string]string{vcsIssuerRequestTokenName: "test"},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusCreated, Body: ioutil.NopCloser(bytes.NewReader([]byte(""))),
			},
		}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("user exists", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleUserName] = []byte(password)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: s},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "username already exists")
	})

	t.Run("save user data error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("save error")},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusCreated, Body: ioutil.NopCloser(strings.NewReader("")),
			},
		}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

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
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: make(map[string][]byte)},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusCreated, Body: ioutil.NopCloser(strings.NewReader("")),
			},
		}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("create vault error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: make(map[string][]byte)},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusInternalServerError, Body: ioutil.NopCloser(strings.NewReader("vault error")),
			},
		}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create vault")
	})

	t.Run("missing national id", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			respValue: &http.Response{
				StatusCode: http.StatusCreated, Body: ioutil.NopCloser(bytes.NewReader([]byte(""))),
			},
		}

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
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.httpClient = &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				fmt.Println(req.URL.Path)
				if req.URL.Path == "/credentials/issueCredential" {
					return &http.Response{
						StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("vcs error")),
					}, nil
				}

				return &http.Response{
					StatusCode: http.StatusCreated,
					Body:       ioutil.NopCloser(strings.NewReader("")),
				}, nil
			},
		}

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(nationalID, sampleNationalID)

		svc.register(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create vc")
	})
}

func TestLogin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		s := make(map[string][]byte)
		s[sampleUserName] = []byte(samplePassword)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: s}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("parse form error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
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

		s := make(map[string][]byte)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: s}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, samplePassword)

		svc.login(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to get user data")
	})

	t.Run("invalid password", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		s := make(map[string][]byte)
		s[sampleUserName] = []byte(samplePassword)

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: s}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add(username, sampleUserName)
		req.Form.Add(password, sampleUserName)

		svc.login(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid password")
	})
}

func TestConnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/connect?userName="+sampleUserName, nil)
		require.NoError(t, err)

		svc.connect(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("no username", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
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
}

func TestDisconnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/disconnect?userName="+sampleUserName, nil)
		require.NoError(t, err)

		svc.disconnect(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("no username", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req, err := http.NewRequest("GET", "/disconnect", nil)
		require.NoError(t, err)

		svc.disconnect(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing username")
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
