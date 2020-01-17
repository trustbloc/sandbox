/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestIssuer_AuthCodeURL(t *testing.T) {
	tokenIssuer := New(&oauth2.Config{})

	w := httptest.NewRecorder()
	u := tokenIssuer.AuthCodeURL(w)
	require.NotEmpty(t, u)
}

func TestIssuer_Client(t *testing.T) {
	tokenIssuer := New(&oauth2.Config{})

	c := tokenIssuer.Client(context.Background(), &oauth2.Token{})
	require.NotNil(t, c)
}

func TestIssuer_Exchange_NoStateCookie(t *testing.T) {
	req, err := getRequest(nil, nil)
	require.NoError(t, err)

	tokenIssuer := New(&oauth2.Config{})

	token, err := tokenIssuer.Exchange(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http: named cookie not present")
	require.Nil(t, token)
}

func TestIssuer_Exchange_NoStateValue(t *testing.T) {
	oauthCookie := &http.Cookie{
		Name:  oauthCookieName,
		Value: "value",
	}

	req, err := getRequest([]*http.Cookie{oauthCookie}, nil)
	require.NoError(t, err)

	tokenIssuer := New(&oauth2.Config{})

	token, err := tokenIssuer.Exchange(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid oauth state")
	require.Nil(t, token)
}

func TestIssuer_Exchange_GetTokenError(t *testing.T) {
	const oauthCookieValue = "some value"

	cookie := &http.Cookie{
		Name:  oauthCookieName,
		Value: oauthCookieValue,
	}
	cookies := []*http.Cookie{cookie}

	formValues := make(map[string][]string)
	formValues["state"] = []string{oauthCookieValue}

	req, err := getRequest(cookies, formValues)
	require.NoError(t, err)

	tokenIssuer := New(&oauth2.Config{})

	token, err := tokenIssuer.Exchange(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Post : unsupported protocol scheme")
	require.Nil(t, token)
}

func getRequest(cookies []*http.Cookie, formValues map[string][]string) (*http.Request, error) {
	req, err := http.NewRequest("method", "path", bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	for _, c := range cookies {
		req.AddCookie(c)
	}

	req.Form = formValues

	return req, nil
}
