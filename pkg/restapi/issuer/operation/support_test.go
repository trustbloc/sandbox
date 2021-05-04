/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/sandbox/pkg/token"
)

func handleRequest(handler Handler, headers map[string]string, path string, addCookie bool) (*bytes.Buffer, int, error) { //nolint:lll
	var cookie *http.Cookie

	if addCookie {
		cookie = &http.Cookie{Name: vcsProfileCookie, Value: "vc-issuer-1"}
	}

	return handleRequestWithCookie(handler, headers, path, cookie)
}

func handleRequestWithCookie(handler Handler, headers map[string]string, path string, cookie *http.Cookie) (*bytes.Buffer, int, error) { //nolint:lll
	if cookie == nil {
		return handleRequestWithCookies(handler, headers, path, nil)
	}

	return handleRequestWithCookies(handler, headers, path, []*http.Cookie{cookie})
}

func handleRequestWithCookies(handler Handler, headers map[string]string, path string, cookies []*http.Cookie) (*bytes.Buffer, int, error) { //nolint:lll
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
	t.Helper()

	svc, err := New(cfg)
	require.NotNil(t, svc)
	require.NoError(t, err)

	return svc, handlerLookup(t, svc, lookup)
}

func getHandlerWithConfig(t *testing.T, lookup string, cfg *Config) Handler {
	t.Helper()

	svc, err := New(cfg)
	require.NotNil(t, svc)
	require.NoError(t, err)

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	t.Helper()

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
	t.Helper()

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
	info token.Introspection
	err  error
}

func (r *mockTokenResolver) Resolve(string) (*token.Introspection, error) {
	if r.err != nil {
		return nil, r.err
	}

	return &r.info, nil
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

func newCreateOIDCHTTPRequest(scope string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com/oauth2/request?scope=%s", scope), nil)
}

func newOIDCCallback(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
}
