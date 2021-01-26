/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

const (
	sampleUserName = "john.smith@example.com"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 2, len(svc.GetRESTHandlers()))
	})

	t.Run("error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStoreHandle: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "acrp store provider : store open error")
		require.Nil(t, svc)
	})
}

func TestRegister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			RegisterHTML:  file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.register(rr, &http.Request{})
		fmt.Print(rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("html error", func(t *testing.T) {
		svc, err := New(&Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
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

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add("username", "john.smith@example.com")

		svc.createAccount(rr, req)
		fmt.Println(rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("user exists", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleUserName] = []byte("password")

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: s},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add("username", sampleUserName)

		svc.createAccount(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "username already exists")
	})

	t.Run("save user data error", func(t *testing.T) {
		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{
				Store: &mockstorage.MockStore{Store: make(map[string][]byte), ErrPut: errors.New("save error")},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		req := &http.Request{Form: make(map[string][]string)}
		req.Form.Add("username", sampleUserName)

		svc.createAccount(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to save user data")
	})

	t.Run("parse form error", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.html")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		svc, err := New(&Config{
			StoreProvider: &mockstorage.Provider{},
			DashboardHTML: file.Name(),
		})
		require.NoError(t, err)
		require.NotNil(t, svc)

		rr := httptest.NewRecorder()

		svc.createAccount(rr, &http.Request{Method: http.MethodPost})
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "unable to parse form data")
	})
}
