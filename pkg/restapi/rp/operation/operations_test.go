/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	svc := New(&Config{})
	require.NotNil(t, svc)
	require.Equal(t, 1, len(svc.GetRESTHandlers()))
}

func TestHTTPPost(t *testing.T) {
	t.Run("test error from http post", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}
		data, err := svc.httpPost("", "", []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "post error")
		require.Empty(t, data)
	})

	t.Run("test response status not ok", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postValue: &http.Response{StatusCode: http.StatusInternalServerError}}
		data, err := svc.httpPost("", "", []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "received unsuccessful POST HTTP status")
		require.Empty(t, data)
	})

	t.Run("test success", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("data"))}}
		data, err := svc.httpPost("", "", []byte(""))
		require.NoError(t, err)
		require.Equal(t, "data", data)
	})
}

func TestVerifyVC(t *testing.T) {
	t.Run("test error from parse form", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		rr := httptest.NewRecorder()
		svc.verifyVC(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse form")
	})

	t.Run("test error from http post", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "post error")
	})

	t.Run("test error from unmarshal post", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("data"))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal vc")
	})

	t.Run("test verify vc failed", func(t *testing.T) {
		svc := New(&Config{})
		b, err := json.Marshal(verifyCredentialResponse{Verified: false, Message: "failed to verify vc"})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify vc")
	})

	t.Run("test vc html not exist", func(t *testing.T) {
		svc := New(&Config{VCHTML: ""})
		b, err := json.Marshal(verifyCredentialResponse{Verified: true})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		svc := New(&Config{VCHTML: file.Name()})
		b, err := json.Marshal(verifyCredentialResponse{Verified: true})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}

		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

type mockHTTPClient struct {
	postValue *http.Response
	postErr   error
}

func (m *mockHTTPClient) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	return m.postValue, m.postErr
}
