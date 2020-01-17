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
)

const flag = "--"

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start issuer", startCmd.Short)
	require.Equal(t, "Start issuer", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartFailure(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, ""}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"host-url value is empty")
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()
	require.Equal(t,
		"Neither host-url (command line flag) nor ISSUER_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartCmdWithMissingAuthURLArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither auth-url (command line flag) nor OAUTH2_ENDPOINT_AUTH_URL (environment variable) have been set.")
}

func TestStartCmdWithMissingTokenURLArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither token-url (command line flag) nor OAUTH2_ENDPOINT_TOKEN_URL (environment variable) have been set.")
}

func TestStartCmdWithMissingRedirectURLArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither redirect-url (command line flag) nor OAUTH2_ISSUER_CLIENT_REDIRECT_URL (environment variable) have been set.") // nolint: lll
}

func TestStartCmdWithMissingClientIDArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither client-id (command line flag) nor OAUTH2_ISSUER_CLIENT_ID (environment variable) have been set.")
}

func TestStartCmdWithMissingClientSecretArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	args = append(args, clientIDArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither client-secret (command line flag) nor OAUTH2_ISSUER_CLIENT_SECRET (environment variable) have been set.")
}

func TestStartCmdWithMissingClientScopesArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	args = append(args, clientIDArg()...)
	args = append(args, clientSecretArg()...)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Contains(t, err.Error(),
		"Neither client-scopes (command line flag) nor OAUTH2_ISSUER_CLIENT_SCOPES (environment variable) have been set.")
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := getValidArgs()
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(endpointAuthURLEnvKey, "endpoint/auth")
	require.Nil(t, err)

	err = os.Setenv(endpointTokenURLEnvKey, "endpoint/token")
	require.Nil(t, err)

	err = os.Setenv(clientRedirectURLEnvKey, "client/redirect")
	require.Nil(t, err)

	err = os.Setenv(clientIDEnvKey, "client-id")
	require.Nil(t, err)

	err = os.Setenv(clientSecretEnvKey, "secret")
	require.Nil(t, err)

	err = os.Setenv(clientScopesEnvKey, "scopes")
	require.Nil(t, err)

	err = os.Setenv(introspectionURLEnvKey, "endpoint/introspect")
	require.Nil(t, err)

	err = os.Setenv(tlsCertFileEnvKey, "cert")
	require.Nil(t, err)

	err = os.Setenv(cmsURLEnvKey, "cms")
	require.Nil(t, err)

	err = os.Setenv(tlsKeyFileEnvKey, "key")
	require.Nil(t, err)

	err = startCmd.Execute()
	require.Nil(t, err)
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

func getValidArgs() []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	args = append(args, clientIDArg()...)
	args = append(args, clientSecretArg()...)
	args = append(args, clientScopesArg()...)
	args = append(args, tokenIntrospectionURLArg()...)
	args = append(args, tlsCertFileArg()...)
	args = append(args, tlsKeyFileArg()...)
	args = append(args, cmsURLArg()...)

	return args
}

func hostURLArg() []string {
	return []string{flag + hostURLFlagName, "localhost:8080"}
}

func endpointAuthURLArg() []string {
	return []string{flag + endpointAuthURLFlagName, "endpoint/auth"}
}

func endpointTokenURLArg() []string {
	return []string{flag + endpointTokenURLFlagName, "endpoint/token"}
}

func clientRedirectURLArg() []string {
	return []string{flag + clientRedirectURLFlagName, "redirect-url"}
}

func clientIDArg() []string {
	return []string{flag + clientIDFlagName, "client-id"}
}

func clientSecretArg() []string {
	return []string{flag + clientSecretFlagName, "secret"}
}

func clientScopesArg() []string {
	return []string{flag + clientScopesFlagName, "openid"}
}

func tokenIntrospectionURLArg() []string {
	return []string{flag + introspectionURLFlagName, "endpoint/introspect"}
}

func tlsCertFileArg() []string {
	return []string{flag + tlsCertFileFlagName, "cert"}
}

func tlsKeyFileArg() []string {
	return []string{flag + tlsKeyFileFlagName, "key"}
}

func cmsURLArg() []string {
	return []string{flag + cmsURLFlagName, "cms"}
}
