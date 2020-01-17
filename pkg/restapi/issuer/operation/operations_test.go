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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const authHeader = "Bearer ABC"

func TestOperation_Login(t *testing.T) {
	handler := getHandler(t, login)
	buff, status, err := handleRequest(handler, nil, login)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_Callback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{}")
	}))
	defer ts.Close()

	headers := make(map[string]string)
	headers["Authorization"] = authHeader

	cfg := &Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{},
		CMSURL: ts.URL}
	handler := getHandlerWithConfig(t, callback, cfg)

	_, status, err := handleRequest(handler, headers, callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
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

func TestOperation_WriteResponse(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}})
	require.NotNil(t, svc)
	svc.writeResponse(&httptest.ResponseRecorder{}, "hello")
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

func getHandler(t *testing.T, lookup string) Handler {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}, TokenResolver: &mockTokenResolver{}})
	require.NotNil(t, svc)

	return handlerLookup(t, svc, lookup)
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
