/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)
		require.Equal(t, 2, len(svc.GetRESTHandlers()))
	})
}

func TestRegister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc := New(&Config{
			RegisterHTML: file.Name(),
		})
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.register(rr, &http.Request{})
		fmt.Print(rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("html error", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.register(rr, &http.Request{})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to load html")
	})
}

func TestCreateAccount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc := New(&Config{
			DashboardHTML: file.Name(),
		})
		require.NotNil(t, svc)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add("username", "john.smith")

		svc.createAccount(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("parse form error", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc := New(&Config{
			DashboardHTML: file.Name(),
		})
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.createAccount(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to parse form data")
	})
}
