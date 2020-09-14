/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config := config()
		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 0, len(svc.GetRESTHandlers()))
	})
}

func config() *Config {
	return &Config{}
}
