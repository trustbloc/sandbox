/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-sandbox/pkg/restapi/rp/operation"
)

func TestController_New(t *testing.T) {
	controller, err := New(&operation.Config{})
	require.NoError(t, err)
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 0, len(ops))
}
