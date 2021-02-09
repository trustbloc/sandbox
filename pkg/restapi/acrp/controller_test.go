/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acrp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/sandbox/pkg/restapi/acrp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, err := New(&operation.Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStoreHandle: errors.New("store open error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create acrp operation")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{StoreProvider: &mockstorage.Provider{}})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 4, len(ops))
}
