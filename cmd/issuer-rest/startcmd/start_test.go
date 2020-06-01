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

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open test.key: no such file or directory")
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start issuer", startCmd.Short)
	require.Equal(t, "Start issuer", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank tls cert arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, endpointAuthURLArg()...)
		args = append(args, endpointTokenURLArg()...)
		args = append(args, clientRedirectURLArg()...)
		args = append(args, clientIDArg()...)
		args = append(args, clientSecretArg()...)
		args = append(args, []string{flag + introspectionURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "introspect-url value is empty", err.Error())
	})

	t.Run("test blank cms url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, endpointAuthURLArg()...)
		args = append(args, endpointTokenURLArg()...)
		args = append(args, clientRedirectURLArg()...)
		args = append(args, clientIDArg()...)
		args = append(args, clientSecretArg()...)
		args = append(args, tokenIntrospectionURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, []string{flag + cmsURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "cms-url value is empty", err.Error())
	})

	t.Run("test blank vcs url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, endpointAuthURLArg()...)
		args = append(args, endpointTokenURLArg()...)
		args = append(args, clientRedirectURLArg()...)
		args = append(args, clientIDArg()...)
		args = append(args, clientSecretArg()...)
		args = append(args, tokenIntrospectionURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, cmsURLArg()...)
		args = append(args, []string{flag + vcsURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "vcs-url value is empty", err.Error())
	})

	t.Run("test blank issuer-adapter url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, endpointAuthURLArg()...)
		args = append(args, endpointTokenURLArg()...)
		args = append(args, clientRedirectURLArg()...)
		args = append(args, clientIDArg()...)
		args = append(args, clientSecretArg()...)
		args = append(args, tokenIntrospectionURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, cmsURLArg()...)
		args = append(args, vcsURLArg()...)
		args = append(args, []string{flag + issuerAdapterURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "issuer-adapter-url value is empty", err.Error())
	})
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
		"Neither introspect-url (command line flag) nor OAUTH2_ENDPOINT_TOKEN_INTROSPECTION_URL (environment variable) have been set.") //nolint:lll
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

	setEnvVars(t)

	err := startCmd.Execute()
	require.Nil(t, err)
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t)

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func setEnvVars(t *testing.T) {
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

	err = os.Setenv(introspectionURLEnvKey, "endpoint/introspect")
	require.Nil(t, err)

	err = os.Setenv(tlsCertFileEnvKey, "cert")
	require.Nil(t, err)

	err = os.Setenv(cmsURLEnvKey, "cms")
	require.Nil(t, err)

	err = os.Setenv(vcsURLEnvKey, "vcs")
	require.Nil(t, err)

	err = os.Setenv(tlsKeyFileEnvKey, "key")
	require.Nil(t, err)

	err = os.Setenv(issuerAdapterURLEnvKey, "issuer-adapter")
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
	args = append(args, tokenIntrospectionURLArg()...)
	args = append(args, tlsCertFileArg()...)
	args = append(args, tlsKeyFileArg()...)
	args = append(args, cmsURLArg()...)
	args = append(args, vcsURLArg()...)
	args = append(args, requestTokensArg()...)
	args = append(args, issuerAdapterURLArg()...)

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

func vcsURLArg() []string {
	return []string{flag + vcsURLFlagName, "vcs"}
}

func requestTokensArg() []string {
	return []string{flag + requestTokensFlagName, "token1=tk1", flag + requestTokensFlagName, "token2=tk2=tk2"}
}

func issuerAdapterURLArg() []string {
	return []string{flag + issuerAdapterURLFlagName, "issuer-adapter"}
}
