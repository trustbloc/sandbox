/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const authHeader = "Bearer ABC"

const testCredentialRequest = `{
"context":"https://www.w3.org/2018/credentials/examples/v1",
"type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "test"
}`

func TestOperation_Login(t *testing.T) {
	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}}
	handler := getHandlerWithConfig(t, login, cfg)

	buff, status, err := handleRequest(handler, nil, login)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_Callback(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer cms.Close()

	router := mux.NewRouter()
	router.HandleFunc("/store", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/credential", func(writer http.ResponseWriter, request *http.Request) {
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
		CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: file.Name()}
	handler := getHandlerWithConfig(t, callback, cfg)

	_, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	// test html not exist
	cfg = &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: cms.URL, VCSURL: vcs.URL, ReceiveVCHTML: ""}
	handler = getHandlerWithConfig(t, callback, cfg)

	body, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, body.String(), "unable to load html")
}

func TestOperation_Callback_ExchangeCodeError(t *testing.T) {
	svc := New(&Config{
		TokenIssuer:   &mockTokenIssuer{err: errors.New("exchange code error")},
		TokenResolver: &mockTokenResolver{}})
	require.NotNil(t, svc)

	handler := handlerLookup(t, svc, callback)

	body, status, err := handleRequest(handler, nil, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body.String(), "failed to exchange code for token")
	require.Contains(t, body.String(), "exchange code error")
}

func TestOperation_Callback_TokenIntrospectionError(t *testing.T) {
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	svc := New(&Config{
		TokenIssuer:   &mockTokenIssuer{},
		TokenResolver: &mockTokenResolver{err: errors.New("token info error")}})
	require.NotNil(t, svc)

	handler := handlerLookup(t, svc, callback)
	body, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body.String(), "failed to get token info")
	require.Contains(t, body.String(), "token info error")
}

func TestOperation_Callback_GetCMSData_Error(t *testing.T) {
	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: "cms"}
	handler := getHandlerWithConfig(t, callback, cfg)

	data, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, data.String(), "unsupported protocol scheme")
}

func TestOperation_Callback_CreateCredential_Error(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer cms.Close()

	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: cms.URL, VCSURL: "vcs"}
	handler := getHandlerWithConfig(t, callback, cfg)

	data, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, data.String(), "unsupported protocol scheme")
}

func TestOperation_Callback_StoreCredential_Error(t *testing.T) {
	cms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer cms.Close()

	vcs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, "{}")
	}))

	defer vcs.Close()

	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: cms.URL, VCSURL: vcs.URL}
	handler := getHandlerWithConfig(t, callback, cfg)

	data, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, data.String(), "failed to store credential")
}

func TestOperation_CreateCredential_Error(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}})
	vc, err := svc.createCredential([]byte(""))
	require.Error(t, err)
	require.Nil(t, vc)
	require.Contains(t, err.Error(), "unexpected end of JSON input")
}

func TestOperation_StoreCredential(t *testing.T) {
	t.Run("store credential success", func(t *testing.T) {
		vcs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "{}")
		}))
		defer vcs.Close()
		svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL})
		err := svc.storeCredential([]byte(testCredentialRequest))
		require.NoError(t, err)
	})
	t.Run("store credential error invalid url ", func(t *testing.T) {
		svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
			VCSURL: "%%&^$"})
		err := svc.storeCredential([]byte(testCredentialRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL escape")
	})
	t.Run("store credential error incorrect status", func(t *testing.T) {
		vcs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, "{}")
		}))
		defer vcs.Close()
		svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}, VCSURL: vcs.URL})
		err := svc.storeCredential([]byte(testCredentialRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "201 Created")
	})
}
func TestOperation_GetCMSData_InvalidURL(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: "xyz:cms"})
	require.NotNil(t, svc)

	data, err := svc.getCMSData(&oauth2.Token{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	require.Nil(t, data)
}

func TestOperation_GetCMSData_InvalidHTTPRequest(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: "http://cms\\"})
	require.NotNil(t, svc)

	data, err := svc.getCMSData(&oauth2.Token{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
	require.Nil(t, data)
}
func TestOperation_CreateCredential_InvalidURL(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		VCSURL: "xyz:vcs"})
	require.NotNil(t, svc)

	data, err := svc.createCredential([]byte("{}"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported protocol scheme")
	require.Nil(t, data)
}

func TestOperation_CreateCredential_InvalidHTTPRequest(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		VCSURL: "http://vcs\\"})
	require.NotNil(t, svc)

	data, err := svc.createCredential([]byte("{}"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid character")
	require.Nil(t, data)
}

func TestOperation_SendHTTPRequest_WrongStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.NoError(t, err)

	data, err := sendHTTPRequest(req, http.DefaultClient, http.StatusInternalServerError)
	require.Error(t, err)
	require.Contains(t, err.Error(), "200 OK")
	require.Nil(t, data)
}

func handleRequest(handler Handler, headers map[string]string, path string) (*bytes.Buffer, int, error) { //nolint:lll
	req, err := http.NewRequest(handler.Method(), path, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, 0, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func getHandlerWithConfig(t *testing.T, lookup string, cfg *Config) Handler {
	svc := New(cfg)
	require.NotNil(t, svc)

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

func (m *mockTokenIssuer) Client(ctx context.Context, t *oauth2.Token) *http.Client {
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
