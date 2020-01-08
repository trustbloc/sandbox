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
	"golang.org/x/oauth2"
)

const flag = "--"

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
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
		"Neither auth-url (command line flag) nor OAUTH2_ENDPOINT_AUTH_URL (environment variable) have been set.")
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

func TestStartIssuerWithBlankHost(t *testing.T) {
	parameters := &issuerParameters{hostURL: ""}

	err := startIssuer(parameters)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "host URL is empty")
}

func TestStartIssuerWithInvalidOAuth2Config(t *testing.T) {
	parameters := &issuerParameters{hostURL: "hostURL", oauth2Config: &oauth2.Config{Endpoint: oauth2.Endpoint{}}}

	err := startIssuer(parameters)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "auth URL is empty")
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

	err = startCmd.Execute()
	require.Nil(t, err)
}

func TestValidateOauth2Config(t *testing.T) {
	config := &oauth2.Config{Endpoint: oauth2.Endpoint{}}

	err := validateOAuth2Config(config)
	require.Contains(t, err.Error(), "auth URL is empty")

	config.Endpoint.AuthURL = "endpoint/auth"

	err = validateOAuth2Config(config)
	require.Contains(t, err.Error(), "token URL is empty")

	config.Endpoint.TokenURL = "endpoint/token"

	err = validateOAuth2Config(config)
	require.Contains(t, err.Error(), "redirect URL is empty")

	config.RedirectURL = "redirect"

	err = validateOAuth2Config(config)
	require.Contains(t, err.Error(), "client ID is empty")

	config.ClientID = "client-id"

	err = validateOAuth2Config(config)
	require.Contains(t, err.Error(), "secret is empty")

	config.ClientSecret = "secret"

	err = validateOAuth2Config(config)
	require.Contains(t, err.Error(), "scopes is empty")

	config.Scopes = []string{"openid"}

	err = validateOAuth2Config(config)
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

func getValidArgs() []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	args = append(args, clientIDArg()...)
	args = append(args, clientSecretArg()...)
	args = append(args, clientScopesArg()...)

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
