/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
)

func TestOperation_Test(t *testing.T) {
	handler := getHandler(t, token)
	buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("sample-connection-id")),
		token)
	require.NoError(t, err)

	// verify response
	require.Contains(t, buf.String(), "hello")
}

func TestOperation_WriteResponse(t *testing.T) {
	svc := New()
	require.NotNil(t, svc)
	svc.writeResponse(&httptest.ResponseRecorder{}, "hello")
}

// getSuccessResponseFromHandler reads response from given http handle func and expects http status to be OK.
func getSuccessResponseFromHandler(handler operation.Handler, requestBody io.Reader,
	path string) (*bytes.Buffer, error) {
	response, status, err := handleRequest(handler, requestBody, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: got %v, want %v",
			status, http.StatusOK)
	}

	return response, err
}

func handleRequest(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
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
	return getHandlerWithError(t, lookup)
}

func getHandlerWithError(t *testing.T, lookup string) Handler {
	svc := New()
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
