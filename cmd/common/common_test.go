/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"

	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
)

const testLogModuleName = "test"

var logger = log.New(testLogModuleName)

func TestSetLogLevel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(logger, "debug")

		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(logger, "mango")

		// Should remain unchanged
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestDBParams(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		expected := &DBParameters{
			URL:     "mem://test",
			Prefix:  "prefix",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		Flags(cmd)
		result, err := DBParams(cmd)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("use default timeout", func(t *testing.T) {
		expected := &DBParameters{
			URL:     "mem://test",
			Prefix:  "prefix",
			Timeout: DatabaseTimeoutDefault,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		err := os.Setenv(DatabaseTimeoutEnvKey, "")
		require.NoError(t, err)
		cmd := &cobra.Command{}
		Flags(cmd)
		result, err := DBParams(cmd)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error if url is missing", func(t *testing.T) {
		expected := &DBParameters{
			Prefix:  "prefix",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		Flags(cmd)
		_, err := DBParams(cmd)
		require.Error(t, err)
	})

	t.Run("error if prefix is missing", func(t *testing.T) {
		expected := &DBParameters{
			URL:     "mem://test",
			Timeout: 30,
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		cmd := &cobra.Command{}
		Flags(cmd)
		_, err := DBParams(cmd)
		require.Error(t, err)
	})

	t.Run("error if timeout has an invalid value", func(t *testing.T) {
		expected := &DBParameters{
			URL:    "mem://test",
			Prefix: "prefix",
		}
		setEnv(t, expected)
		defer unsetEnv(t)
		err := os.Setenv(DatabaseTimeoutEnvKey, "invalid")
		require.NoError(t, err)
		cmd := &cobra.Command{}
		Flags(cmd)
		_, err = DBParams(cmd)
		require.Error(t, err)
	})
}

func TestInitEdgeStore(t *testing.T) {
	t.Run("inits ok", func(t *testing.T) {
		s, err := InitStore(&DBParameters{
			URL:     "mem://test",
			Prefix:  "test",
			Timeout: 30,
		}, log.New("test"))
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error if url format is invalid", func(t *testing.T) {
		_, err := InitStore(&DBParameters{
			URL:     "invalid",
			Prefix:  "test",
			Timeout: 30,
		}, log.New("test"))
		require.Error(t, err)
	})

	t.Run("error if driver is not supported", func(t *testing.T) {
		_, err := InitStore(&DBParameters{
			URL:     "unsupported://test",
			Prefix:  "test",
			Timeout: 30,
		}, log.New("test"))
		require.Error(t, err)
	})

	t.Run("error if cannot connect to store", func(t *testing.T) {
		t.Run("mysql", func(t *testing.T) {
			_, err := InitStore(&DBParameters{
				URL:     "mysql://test:secret@tcp(localhost:5984)",
				Prefix:  "test",
				Timeout: 1,
			}, log.New("test"))
			require.Error(t, err)
		})
		t.Run("couchdb", func(t *testing.T) {
			_, err := InitStore(&DBParameters{
				URL:     "couchdb://",
				Prefix:  "test",
				Timeout: 1,
			}, log.New("test"))
			require.EqualError(t, err, "failed to connect to storage at  : failed to ping couchDB: "+
				"url can't be blank")
		})
		t.Run("mongodb", func(t *testing.T) {
			_, err := InitStore(&DBParameters{
				URL:     "mongodb://",
				Prefix:  "test",
				Timeout: 1,
			}, log.New("test"))
			require.EqualError(t, err, "failed to connect to storage at mongodb:// : "+
				"failed to create a new MongoDB client: error parsing uri: must have at least 1 host")
		})
	})
}

func TestCreateLDStoreProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := CreateLDStoreProvider(mockstorage.NewMockStoreProvider())

		require.NotNil(t, provider)
		require.NoError(t, err)

		require.NotNil(t, provider.JSONLDContextStore())
		require.NotNil(t, provider.JSONLDRemoteProviderStore())
	})

	t.Run("Fail to create JSON-LD context store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.FailNamespace = ldstore.ContextStoreName

		provider, err := CreateLDStoreProvider(storageProvider)

		require.Nil(t, provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create JSON-LD context store")
	})

	t.Run("Fail to create remote provider store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.FailNamespace = ldstore.RemoteProviderStoreName

		provider, err := CreateLDStoreProvider(storageProvider)

		require.Nil(t, provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create remote provider store")
	})
}

func TestCreateJSONLDDocumentLoader(t *testing.T) {
	const sampleJSONLDContext = `
	{
	  "@context": {
		"name": "http://xmlns.com/foaf/0.1/name",
		"homepage": {
		  "@id": "http://xmlns.com/foaf/0.1/homepage",
		  "@type": "@id"
		}
	  }
	}`

	client := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(sampleJSONLDContext))),
			}, nil
		},
	}

	t.Run("Success", func(t *testing.T) {
		ldStore := &mockLDStoreProvider{
			ContextStore:        mockldstore.NewMockContextStore(),
			RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
		}

		loader, err := CreateJSONLDDocumentLoader(ldStore, client, []string{"endpoint"})

		require.NotNil(t, loader)
		require.NoError(t, err)
	})

	t.Run("Fail to create a new document loader", func(t *testing.T) {
		contextStore := mockldstore.NewMockContextStore()
		contextStore.ErrImport = errors.New("import error")

		ldStore := &mockLDStoreProvider{
			ContextStore:        contextStore,
			RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
		}

		loader, err := CreateJSONLDDocumentLoader(ldStore, client, []string{"endpoint"})

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "new document loader")
	})
}

type mockLDStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *mockLDStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *mockLDStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func resetLoggingLevels() {
	log.SetLevel("", log.INFO)
}

func setEnv(t *testing.T, values *DBParameters) {
	t.Helper()

	err := os.Setenv(DatabaseURLEnvKey, values.URL)
	require.NoError(t, err)

	err = os.Setenv(DatabasePrefixEnvKey, values.Prefix)
	require.NoError(t, err)

	err = os.Setenv(DatabaseTimeoutEnvKey, strconv.FormatUint(values.Timeout, 10))
	require.NoError(t, err)
}

func unsetEnv(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(DatabaseURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(DatabasePrefixEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(DatabaseTimeoutEnvKey)
	require.NoError(t, err)
}
