/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"
	"strings"

	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsent_New(t *testing.T) {
	tests := []struct {
		name     string
		adminURL string
		err      string
	}{
		{
			name:     "initialize with valid admin URL",
			adminURL: "sampleURL",
		},
		{
			name:     "initialize with valid admin URL",
			adminURL: " ?&=#+%!<>#\"{}|\\^[];",
			err:      "invalid URL escape",
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			server, err := newConsentServer(tc.adminURL, true)
			if tc.err != "" {
				require.Contains(t, err.Error(), tc.err)
				return
			}

			require.NotNil(t, server)
			require.NotNil(t, server.hydraClient)
			require.NotNil(t, server.loginTemplate)
			require.NotNil(t, server.consentTemplate)
			require.True(t, server.skipSSLCheck)
		})
	}
}

func TestConsent_buildConsentServer(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		err  string
	}{
		{
			name: "initialize without required ENV variables",
			env:  map[string]string{},
			err:  "admin URL is required",
		},
		{
			name: "initialize with only required ENV variables",
			env: map[string]string{
				adminURLEnvKey: "sampleURL",
			},
		},
		{
			name: "initialize with invalid ski ssl check ENV variable",
			env: map[string]string{
				adminURLEnvKey:     "sampleURL",
				skipSSLCheckEnvKey: "InVaLid",
			},
		},
		{
			name: "initialize with valid ENV variables",
			env: map[string]string{
				adminURLEnvKey:     "sampleURL",
				skipSSLCheckEnvKey: "true",
			},
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				require.NoError(t, os.Setenv(k, v))
			}

			server, err := buildConsentServer()
			if tc.err != "" {
				require.Contains(t, err.Error(), tc.err)
			} else {
				require.NotNil(t, server)
				require.NotNil(t, server.hydraClient)
				require.NotNil(t, server.loginTemplate)
				require.NotNil(t, server.consentTemplate)
			}
		})
	}
}

func TestConsentServer_Login(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/oauth2/auth/requests/login/accept" {
			fmt.Fprint(res, `{"redirect_to":"sampleURL"}`)
		}

		res.WriteHeader(http.StatusOK)
	}))

	defer func() { testServer.Close() }()

	tests := []struct {
		name           string
		adminURL       string
		method         string
		url            string
		form           map[string][]string
		responseHTML   []string
		responseStatus int
		err            string
	}{
		{
			name:           "/login GET SUCCESS",
			adminURL:       testServer.URL,
			method:         http.MethodGet,
			url:            "?login_challenge=12345",
			responseHTML:   []string{"<title>Login Page</title>", `name="challenge" value="12345"`},
			responseStatus: http.StatusOK,
		},
		{
			name:           "/login POST FAILURE (missing form body)",
			adminURL:       testServer.URL,
			method:         http.MethodPost,
			url:            "?login_challenge=12345",
			err:            "missing form body",
			responseStatus: http.StatusOK,
		},
		{
			name:     "/login POST FAILURE (missing login credentials)",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"email":     {"uname"},
				"challenge": {"12345"},
			},
			responseStatus: http.StatusForbidden,
		},
		{
			name:     "/login POST FAILURE (missing challenge)",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"email":    {"uname"},
				"password": {"pwd"},
			},
			responseStatus: http.StatusForbidden,
		},
		{
			name:     "/login POST SUCCESS",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"email":     {"uname"},
				"password":  {"pwd"},
				"challenge": {"12345"},
			},
			responseStatus: http.StatusOK,
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			server, err := newConsentServer(tc.adminURL, true)
			require.NotNil(t, server)
			require.NoError(t, err)

			req, err := http.NewRequest(tc.method, tc.url, nil)
			require.NoError(t, err)

			if tc.form != nil {
				req.PostForm = url.Values(tc.form)
			}

			res := httptest.NewRecorder()

			server.login(res, req)

			if len(tc.responseHTML) > 0 {
				for _, html := range tc.responseHTML {
					require.Contains(t, res.Body.String(), html)
				}
			}

			if tc.err != "" {
				require.Contains(t, res.Body.String(), tc.err)
			}
			require.Equal(t, tc.responseStatus, res.Code, res.Body.String())
		})
	}
}

func TestConsentServer_Consent(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.RequestURI, "/oauth2/auth/requests/consent/") {
			fmt.Fprint(res, `{"redirect_to":"sampleURL"}`)
		}
		res.WriteHeader(http.StatusOK)
	}))

	defer func() { testServer.Close() }()

	tests := []struct {
		name           string
		adminURL       string
		method         string
		url            string
		form           map[string][]string
		responseHTML   []string
		responseStatus int
		err            string
	}{
		{
			name:           "/consent GET SUCCESS",
			adminURL:       testServer.URL,
			method:         http.MethodGet,
			url:            "?consent_challenge=12345",
			responseHTML:   []string{"<title>Consent Page</title>"},
			responseStatus: http.StatusOK,
		},
		{
			name:           "/consent POST FAILURE (missing form body)",
			adminURL:       testServer.URL,
			method:         http.MethodPost,
			err:            "missing form body",
			responseStatus: http.StatusOK,
		},
		{
			name:           "/consent POST FAILURE (missing submit)",
			adminURL:       testServer.URL,
			method:         http.MethodPost,
			form:           map[string][]string{},
			responseStatus: http.StatusBadRequest,
			err:            "consent value missing",
		},
		{
			name:     "/consent POST FAILURE (invalid submit value)",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"submit": {"xyz"},
			},
			responseStatus: http.StatusBadRequest,
			err:            "incorrect consent value",
		},
		{
			name:     "/consent POST accept consent value",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"submit": {"accept"},
			},
			responseStatus: http.StatusOK,
		},
		{
			name:     "/consent POST accept consent value",
			adminURL: testServer.URL,
			method:   http.MethodPost,
			form: map[string][]string{
				"submit": {"reject"},
			},
			responseStatus: http.StatusOK,
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			server, err := newConsentServer(tc.adminURL, true)
			require.NotNil(t, server)
			require.NoError(t, err)

			req, err := http.NewRequest(tc.method, tc.url, nil)
			require.NoError(t, err)

			if tc.form != nil {
				req.PostForm = url.Values(tc.form)
			}

			res := httptest.NewRecorder()

			server.consent(res, req)

			if len(tc.responseHTML) > 0 {
				for _, html := range tc.responseHTML {
					require.Contains(t, res.Body.String(), html)
				}
			}

			if tc.err != "" {
				require.Contains(t, res.Body.String(), tc.err)
			}
			require.Equal(t, tc.responseStatus, res.Code, res.Body.String())
		})
	}
}
