/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpts(t *testing.T) {
	tokenIssuer := New("", WithTLSConfig(&tls.Config{ServerName: "name", MinVersion: tls.VersionTLS12}))
	require.NotNil(t, tokenIssuer.httpClient.Transport)
}

func TestResolver_Resolve(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, jsonBody)
	}))
	defer ts.Close()

	tokenIssuer := New(ts.URL)

	tk, err := tokenIssuer.Resolve("token")
	require.NoError(t, err)
	require.NotNil(t, tk)
	require.Equal(t, true, tk.Active)
	require.Equal(t, "a@b.com", tk.Subject)
}

func TestResolver_Resolve_Error(t *testing.T) {
	tokenIssuer := New("http://localhost/introspect")

	tk, err := tokenIssuer.Resolve("token")
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection refused")
	require.Empty(t, tk)
}

func TestResolver_GetTokenInfo(t *testing.T) {
	w := httptest.NewRecorder()
	_, err := w.WriteString(jsonBody)
	require.NoError(t, err)

	resp := w.Result()

	tk, err := getTokenInfo(resp)
	require.NoError(t, err)
	require.NotNil(t, tk)
	require.Equal(t, true, tk.Active)
	require.Equal(t, "a@b.com", tk.Subject)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestResolver_GetTokenInfo_StatusNotOK(t *testing.T) {
	tk, err := getTokenInfo(&http.Response{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "http status code is not ok")
	require.Nil(t, tk)
}

func TestResolver_GetTokenInfo_ReadBodyError(t *testing.T) {
	w := httptest.NewRecorder()
	resp := w.Result()

	resp.Body = &mockReader{}

	tk, err := getTokenInfo(resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reader error")
	require.Nil(t, tk)

	err = resp.Body.Close()
	require.NoError(t, err)
}

func TestResolver_GetTokenInfo_JSONUnmarshalError(t *testing.T) {
	w := httptest.NewRecorder()
	resp := w.Result()

	tk, err := getTokenInfo(resp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected end of JSON input")
	require.Nil(t, tk)

	err = resp.Body.Close()
	require.NoError(t, err)
}

type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func (r *mockReader) Close() error {
	return nil
}

const jsonBody = `{
  "active": true,
  "sub": "a@b.com"
}
`
