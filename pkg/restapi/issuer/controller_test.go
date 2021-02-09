/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/sandbox/pkg/restapi/issuer/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		controller, err := New(&operation.Config{StoreProvider: &mockstorage.Provider{}})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test new - error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("store create error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer store provider : store create error")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{StoreProvider: &mockstorage.Provider{}})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 12, len(ops))
}
