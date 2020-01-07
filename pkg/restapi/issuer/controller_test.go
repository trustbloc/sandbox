/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	controller, err := New()
	require.NoError(t, err)
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New()
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 1, len(ops))
}
