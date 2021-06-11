/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acerp

import (
	"errors"
	"testing"

	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sandbox/pkg/restapi/acerp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &mockstorage.Provider{},
			ComparatorURL: "http://comp.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStore: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create ace-rp operation")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{
		StoreProvider: &mockstorage.Provider{},
		ComparatorURL: "http://comp.example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 19, len(ops))
}
