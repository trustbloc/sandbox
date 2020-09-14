/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-sandbox/cmd/common"
)

const flag = "--"

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return nil
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open test.key: no such file or directory")
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start upload credential", startCmd.Short)
	require.Equal(t, "Start upload credential", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()
	require.Error(t, err)
	require.Equal(t,
		"Neither host-url (command line flag) nor UPLOAD_CREDENTIAL_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := getValidArgs(log.ParseString(log.ERROR))
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NoError(t, err)
	require.Equal(t, log.ERROR, log.GetLevel(""))
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)
	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func getValidArgs(logLevel string) []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, tlsCertFileArg()...)
	args = append(args, tlsKeyFileArg()...)
	args = append(args, requestTokensArg()...)

	if logLevel != "" {
		args = append(args, logLevelArg(logLevel)...)
	}

	return args
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)
	defer unsetEnvVars(t)

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(tlsCertFileEnvKey, "cert")
	require.Nil(t, err)

	err = os.Setenv(tlsKeyFileEnvKey, "key")
	require.Nil(t, err)

	err = os.Setenv(common.DatabaseURLEnvKey, "mem://test")
	require.NoError(t, err)

	err = os.Setenv(common.DatabasePrefixEnvKey, "test")
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	err := os.Unsetenv(hostURLEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(tlsCertFileEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(tlsKeyFileEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(common.DatabaseURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(common.DatabasePrefixEnvKey)
	require.NoError(t, err)
}

func hostURLArg() []string {
	return []string{flag + hostURLFlagName, "localhost:8080"}
}

func tlsCertFileArg() []string {
	return []string{flag + tlsCertFileFlagName, "cert"}
}

func tlsKeyFileArg() []string {
	return []string{flag + tlsKeyFileFlagName, "key"}
}

func requestTokensArg() []string {
	return []string{flag + requestTokensFlagName, "token1=tk1", flag + requestTokensFlagName, "token2=tk2=tk2"}
}

func logLevelArg(logLevel string) []string {
	return []string{flag + common.LogLevelFlagName, logLevel}
}
