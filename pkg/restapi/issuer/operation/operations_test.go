/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
)

func TestOperation_Login(t *testing.T) {
	handler := getHandler(t, login)
	buff, status, err := handleRequest(handler, bytes.NewBuffer([]byte("")), login)
	require.NoError(t, err)
	require.Contains(t, buff.String(), "Temporary Redirect")
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_Callback(t *testing.T) {
	handler := getHandler(t, callback)
	_, status, err := handleRequest(handler, bytes.NewBuffer([]byte("")), callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
}

func TestOperation_Callback_Error(t *testing.T) {
	handler := getHandlerWithError(t, callback, errors.New("some error"))
	_, status, err := handleRequest(handler, bytes.NewBuffer([]byte("")), callback)
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, status)
}

func TestOperation_WriteResponse(t *testing.T) {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{}})
	require.NotNil(t, svc)
	svc.writeResponse(&httptest.ResponseRecorder{}, "hello")
}

func handleRequest(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) { //nolint:lll
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, 0, err
	}

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func getHandler(t *testing.T, lookup string) Handler {
	return getHandlerWithError(t, lookup, nil)
}

func getHandlerWithError(t *testing.T, lookup string, err error) Handler {
	svc := New(&Config{TokenIssuer: &mockTokenIssuer{err: err}})
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
