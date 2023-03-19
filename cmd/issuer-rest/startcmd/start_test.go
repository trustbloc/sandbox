/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sandbox/cmd/common"
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

		f, err := os.CreateTemp("", "profiles-mapping.json")
		require.NoError(t, err)

		_, err = f.Write([]byte(`[{}]`))
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, os.Remove(f.Name()))
		})

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
		args = append(args, profilesFilePathArg(f.Name())...)
		args = append(args, cmsURLArg()...)
		args = append(args, vcsURLArg()...)
		args = append(args, []string{flag + issuerAdapterURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "issuer-adapter-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	startCmd.SetArgs(profilesFilePathArg("profiles-mapping.json"))

	err := startCmd.Execute()
	require.Equal(t,
		"Neither host-url (command line flag) nor ISSUER_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartCmdWithMissingProfilesFilePathArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, endpointAuthURLArg()...)
	args = append(args, endpointTokenURLArg()...)
	args = append(args, clientRedirectURLArg()...)
	args = append(args, clientIDArg()...)
	args = append(args, clientSecretArg()...)
	args = append(args, tokenIntrospectionURLArg()...)
	args = append(args, cmsURLArg()...)
	args = append(args, vcsURLArg()...)

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Equal(t,
		"Neither profiles-mapping-file-path (command line flag) nor "+
			"ISSUER_PROFILES_MAPPING_FILE_PATH (environment variable) have been set.",
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

func TestDatabaseTypeArg(t *testing.T) {
	t.Run("test database url - missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		f, err := os.CreateTemp("", "profiles-mapping.json")
		require.NoError(t, err)

		_, err = f.Write([]byte(`[{}]`))
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, os.Remove(f.Name()))
		})

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
		args = append(args, profilesFilePathArg(f.Name())...)
		args = append(args, cmsURLArg()...)
		args = append(args, vcsURLArg()...)
		args = append(args, issuerAdapterURLArg()...)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither database-url (command line flag) nor DATABASE_URL (environment variable) have been set.")
	})

	t.Run("test database type - invalid driver", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		f, err := os.CreateTemp("", "profiles-mapping.json")
		require.NoError(t, err)

		_, err = f.Write([]byte(`[{}]`))
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, os.Remove(f.Name()))
		})

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
		args = append(args, profilesFilePathArg(f.Name())...)
		args = append(args, cmsURLArg()...)
		args = append(args, vcsURLArg()...)
		args = append(args, issuerAdapterURLArg()...)
		args = append(args, []string{flag + common.DatabasePrefixFlagName, "test"}...)
		args = append(args, []string{flag + common.DatabaseURLFlagName, "invalid-driver://test"}...)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Contains(t, err.Error(), "unsupported storage driver: invalid-driver")
	})
}

func TestGetCertPool(t *testing.T) {
	require.Error(t, startIssuer(&issuerParameters{tlsCACerts: []string{"ww"}}))
}

func TestOIDCParam(t *testing.T) {
	t.Run("test oidc param - error", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		f, err := os.CreateTemp("", "profiles-mapping.json")
		require.NoError(t, err)

		_, err = f.Write([]byte(`[{}]`))
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, os.Remove(f.Name()))
		})

		temp := getOIDCParametersFunc
		getOIDCParametersFunc = func(cmd *cobra.Command) (*oidcParameters, error) {
			return nil, fmt.Errorf("oidc param error")
		}
		defer func() { getOIDCParametersFunc = temp }()

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
		args = append(args, profilesFilePathArg(f.Name())...)
		args = append(args, cmsURLArg()...)
		args = append(args, vcsURLArg()...)
		args = append(args, issuerAdapterURLArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Contains(t, err.Error(), "oidc param error")
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	f, err := os.CreateTemp("", "profiles-mapping.json")
	require.NoError(t, err)

	_, err = f.Write([]byte(`[{}]`))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.Remove(f.Name()))
	})

	args := getValidArgs(log.ParseString(log.ERROR), f.Name())
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, log.ERROR, log.GetLevel(""))
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

	require.NoError(t, os.Unsetenv(tlsSystemCertPoolEnvKey))
}

func TestStartCmdReadProfiles(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "empty file",
			content: "",
			wantErr: "decode profiles",
		},
		{
			name:    "no profiles",
			content: "[]",
			wantErr: "at least one profile must be specified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startCmd := GetStartCmd(&mockServer{})

			f, err := os.CreateTemp("", "profiles-mapping.json")
			require.NoError(t, err)

			_, err = f.Write([]byte(tt.content))
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, os.Remove(f.Name()))
			})

			args := getValidArgs(log.ParseString(log.ERROR), f.Name())
			startCmd.SetArgs(args)

			err = startCmd.Execute()
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func setEnvVars(t *testing.T) {
	t.Helper()

	f, err := os.CreateTemp("", "profiles-mapping.json")
	require.NoError(t, err)

	_, err = f.Write([]byte(`[{}]`))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.Remove(f.Name()))
	})

	err = os.Setenv(hostURLEnvKey, "localhost:8080")
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

	err = os.Setenv(profilesFilePathEnvKey, f.Name())
	require.Nil(t, err)

	err = os.Setenv(issuerAdapterURLEnvKey, "issuer-adapter")
	require.Nil(t, err)

	err = os.Setenv(common.DatabaseURLEnvKey, "mem://test")
	require.NoError(t, err)

	err = os.Setenv(common.DatabasePrefixEnvKey, "test")
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func getValidArgs(logLevel string, profilesFilePath string) []string {
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
	args = append(args, databaseURLArg()...)
	args = append(args, databasePrefixArg()...)
	args = append(args, profilesFilePathArg(profilesFilePath)...)

	if logLevel != "" {
		args = append(args, logLevelArg(logLevel)...)
	}

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

func logLevelArg(logLevel string) []string {
	return []string{flag + common.LogLevelFlagName, logLevel}
}

func databaseURLArg() []string {
	return []string{flag + common.DatabaseURLFlagName, "mem://test"}
}

func databasePrefixArg() []string {
	return []string{flag + common.DatabasePrefixFlagName, "database-prefix"}
}

func profilesFilePathArg(path string) []string {
	return []string{flag + profilesFilePathFlagName, path}
}
