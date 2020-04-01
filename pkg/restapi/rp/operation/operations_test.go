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
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
)

const (
	validContext = `"@context":["https://www.w3.org/2018/credentials/v1"]`

	validVC = `{` +
		validContext + `,
	  "id": "http://example.edu/credentials/1872",
	  "type": "VerifiableCredential",
	  "credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	  },
	  "issuer": {
		"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"name": "Example University"
	  },
	  "issuanceDate": "2010-01-01T19:23:24Z",
	  "credentialStatus": {
		"id": "https://example.gov/status/24",
		"type": "CredentialStatusList2017"
	  }
	}`

	validVP = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		"type": "VerifiablePresentation",
		"verifiableCredential": [{
			"@context": [
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1"
			],
			"id": "http://example.edu/credentials/1872",
			"type": "VerifiableCredential",
			"credentialSubject": {
				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
			},
			"issuer": {
				"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
				"name": "Example University"
			},
			"issuanceDate": "2010-01-01T19:23:24Z",
			"credentialStatus": {
				"id": "https://example.gov/status/24",
				"type": "CredentialStatusList2017"
			}
		}],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"refreshService": {
			"id": "https://example.edu/refresh/3732",
			"type": "ManualRefreshService2018"
		}
	}`
)

func TestNew(t *testing.T) {
	svc := New(&Config{})
	require.NotNil(t, svc)
	require.Equal(t, 2, len(svc.GetRESTHandlers()))
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

	t.Run("test error from unmarshal request", func(t *testing.T) {
		svc := New(&Config{})

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{"vc"}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal request")
	})

	t.Run("test error from http post", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "post error")
	})

	t.Run("test verify vc failed", func(t *testing.T) {
		svc := New(&Config{})
		b, err := json.Marshal(edgesvcops.CredentialsVerificationFailResponse{
			Checks: []edgesvcops.CredentialsVerificationCheckResult{
				{Check: "status", Error: "status check failed"},
			},
		})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "status check failed")
	})

	t.Run("test vc html not exist", func(t *testing.T) {
		svc := New(&Config{VCHTML: ""})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVC}
		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		svc := New(&Config{VCHTML: file.Name()})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVC}

		svc.verifyVC(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestVerifyVP(t *testing.T) {
	t.Run("test error from parse form missing body", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("post error")}

		rr := httptest.NewRecorder()
		svc.verifyVP(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse form: missing form body")
	})

	t.Run("test error from unmarshal post", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("data"))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vpDataInput"] = []string{"vp"}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to unmarshal request")
	})

	t.Run("test error due to invalid form data", func(t *testing.T) {
		svc := New(&Config{})
		svc.client = &mockHTTPClient{postErr: fmt.Errorf("invalid form data")}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to verify: invalid form data")
	})

	t.Run("test verify vp failed", func(t *testing.T) {
		svc := New(&Config{})
		b, err := json.Marshal(edgesvcops.CredentialsVerificationFailResponse{
			Checks: []edgesvcops.CredentialsVerificationCheckResult{
				{Check: "status", Error: "status check failed"},
			},
		})
		require.NoError(t, err)
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusBadRequest, Body: ioutil.NopCloser(strings.NewReader(string(b)))}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "status check failed")
	})

	t.Run("test vp html not exist", func(t *testing.T) {
		svc := New(&Config{VCHTML: ""})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}
		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})

	t.Run("test resp read fail", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		svc := New(&Config{VPHTML: file.Name()})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}

		svc.verifyVP(rr, &http.Request{Form: m})
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		svc := New(&Config{VPHTML: file.Name()})
		svc.client = &mockHTTPClient{postValue: &http.Response{
			StatusCode: http.StatusOK, Body: nil}}

		rr := httptest.NewRecorder()
		m := make(map[string][]string)
		m["vcDataInput"] = []string{validVP}

		svc.verifyVP(rr, &http.Request{Form: m})
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
