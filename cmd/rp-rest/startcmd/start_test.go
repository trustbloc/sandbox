/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
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
	require.Equal(t, "Start rp", startCmd.Short)
	require.Equal(t, "Start rp", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank vcs service url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, []string{flag + vcsURLFlagName, ""}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "vcs-url value is empty", err.Error())
	})
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()
	require.Equal(t,
		"Neither host-url (command line flag) nor RP_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	path, cleanup := newTestOIDCProvider()
	defer cleanup()

	args := getValidArgs(log.ParseString(log.ERROR), path)
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NoError(t, err)
	require.Equal(t, log.ERROR, log.GetLevel(""))
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	path, cleanup := newTestOIDCProvider()
	defer cleanup()

	setEnvVars(t, path)
	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmd(t *testing.T) {
	t.Run("missing database url", func(t *testing.T) {
		oidcProviderURL, cleanup := newTestOIDCProvider()
		defer cleanup()

		cmd := GetStartCmd(&mockServer{})
		args := hostURLArg()
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, vcsServiceURLArg()...)
		args = append(args, requestTokensArg()...)
		args = append(args, oidcClientIDArg()...)
		args = append(args, oidcClientSecretArg()...)
		args = append(args, databaseURLPrefix()...)
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)

		cmd.SetArgs(args)
		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Neither database-url (command line flag) nor DATABASE_URL (environment variable) have been set.")
	})

	t.Run("invalid database url format", func(t *testing.T) {
		oidcProviderURL, cleanup := newTestOIDCProvider()
		defer cleanup()

		cmd := GetStartCmd(&mockServer{})
		args := hostURLArg()
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, vcsServiceURLArg()...)
		args = append(args, requestTokensArg()...)
		args = append(args, oidcClientIDArg()...)
		args = append(args, oidcClientSecretArg()...)
		args = append(args, flag+common.DatabaseURLFlagName, "invalid_format")
		args = append(args, databaseURLPrefix()...)
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)

		cmd.SetArgs(args)
		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid dbURL")
	})

	t.Run("missing database prefix", func(t *testing.T) {
		oidcProviderURL, cleanup := newTestOIDCProvider()
		defer cleanup()

		cmd := GetStartCmd(&mockServer{})
		args := hostURLArg()
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, vcsServiceURLArg()...)
		args = append(args, requestTokensArg()...)
		args = append(args, oidcClientIDArg()...)
		args = append(args, oidcClientSecretArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)

		cmd.SetArgs(args)
		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"Neither database-prefix (command line flag) nor DATABASE_PREFIX (environment variable) have been set.")
	})

	t.Run("invalid database timeout", func(t *testing.T) {
		oidcProviderURL, cleanup := newTestOIDCProvider()
		defer cleanup()

		cmd := GetStartCmd(&mockServer{})
		args := hostURLArg()
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, vcsServiceURLArg()...)
		args = append(args, requestTokensArg()...)
		args = append(args, oidcClientIDArg()...)
		args = append(args, oidcClientSecretArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databaseURLPrefix()...)
		args = append(args, flag+common.DatabaseTimeoutFlagName, "invalid")
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)

		cmd.SetArgs(args)
		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse dbTimeout")
	})
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

func getValidArgs(logLevel, oidcProviderURL string) []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, tlsCertFileArg()...)
	args = append(args, tlsKeyFileArg()...)
	args = append(args, vcsServiceURLArg()...)
	args = append(args, requestTokensArg()...)
	args = append(args, oidcClientIDArg()...)
	args = append(args, oidcClientSecretArg()...)
	args = append(args, databaseURLArg()...)
	args = append(args, databaseURLPrefix()...)

	if logLevel != "" {
		args = append(args, logLevelArg(logLevel)...)
	}

	if oidcProviderURL != "" {
		args = append(args, oidcProviderURLArg(oidcProviderURL)...)
	}

	return args
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	path, cleanup := newTestOIDCProvider()
	defer cleanup()

	setEnvVars(t, path)
	defer unsetEnvVars(t)

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func setEnvVars(t *testing.T, oidcProviderURL string) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(tlsCertFileEnvKey, "cert")
	require.Nil(t, err)

	err = os.Setenv(tlsKeyFileEnvKey, "key")
	require.Nil(t, err)

	err = os.Setenv(vcsURLEnvKey, "localhost:8081")
	require.Nil(t, err)

	err = os.Setenv(oidcProviderURLEnvKey, oidcProviderURL)
	require.NoError(t, err)

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

	err = os.Unsetenv(vcsURLEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(oidcProviderURLEnvKey)
	require.NoError(t, err)

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

func vcsServiceURLArg() []string {
	return []string{flag + vcsURLFlagName, "localhost:8081"}
}

func requestTokensArg() []string {
	return []string{flag + requestTokensFlagName, "token1=tk1", flag + requestTokensFlagName, "token2=tk2=tk2"}
}

func logLevelArg(logLevel string) []string {
	return []string{flag + common.LogLevelFlagName, logLevel}
}

func oidcProviderURLArg(oidcProviderURL string) []string {
	return []string{flag + oidcProviderURLFlagName, oidcProviderURL}
}

func oidcClientIDArg() []string {
	return []string{flag + oidcClientIDFlagName, uuid.New().String()}
}

func oidcClientSecretArg() []string {
	return []string{flag + oidcClientSecretFlagName, uuid.New().String()}
}

func databaseURLArg() []string {
	return []string{flag + common.DatabaseURLFlagName, "mem://test"}
}

func databaseURLPrefix() []string {
	return []string{flag + common.DatabasePrefixFlagName, "test"}
}

func newTestOIDCProvider() (string, func()) {
	h := &testOIDCProvider{}
	srv := httptest.NewServer(h)
	h.baseURL = srv.URL

	return srv.URL, srv.Close
}

type oidcConfigJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type testOIDCProvider struct {
	baseURL string
}

func (t *testOIDCProvider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	response, err := json.Marshal(&oidcConfigJSON{
		Issuer:      t.baseURL,
		AuthURL:     fmt.Sprintf("%s/oauth2/auth", t.baseURL),
		TokenURL:    fmt.Sprintf("%s/oauth2/token", t.baseURL),
		JWKSURL:     fmt.Sprintf("%s/oauth2/certs", t.baseURL),
		UserInfoURL: fmt.Sprintf("%s/oauth2/userinfo", t.baseURL),
		Algorithms:  []string{"RS256"},
	})
	if err != nil {
		panic(err)
	}

	_, err = w.Write(response)
	if err != nil {
		panic(err)
	}
}
