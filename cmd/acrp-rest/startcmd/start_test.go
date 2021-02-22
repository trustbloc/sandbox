/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"net/http/httptest"
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
	require.Equal(t, "Start AC RP", startCmd.Short)
	require.Equal(t, "Start Anonymous Comparator RP", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()
	require.Equal(t,
		"Neither host-url (command line flag) nor ACRP_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestDemoModeArg(t *testing.T) {
	t.Run("missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither demo-mode (command line flag) nor ACRP_DEMO_MODE (environment variable) have been set.")
	})

	t.Run("invalid value", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		args = append(args, demoModeArg("test")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(), "invalid demo mode : test")
	})
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
	args = append(args, databaseURLArg()...)
	args = append(args, databasePrefixArg()...)
	args = append(args, demoModeArg("rev")...)
	args = append(args, vaultServerURLArg()...)
	args = append(args, vcIssuerURLArg()...)
	args = append(args, hostExternalURLArg()...)
	args = append(args, accountLinkProfileArg()...)
	args = append(args, requestTokensArg()...)
	args = append(args, comparatorURLArg()...)

	if logLevel != "" {
		args = append(args, logLevelArg(logLevel)...)
	}

	return args
}

func TestDatabaseTypeArg(t *testing.T) {
	t.Run("test database url - missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither database-url (command line flag) nor DATABASE_URL (environment variable) have been set.")
	})

	t.Run("test database type - invalid driver", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, demoModeArg("rev")...)
		args = append(args, vaultServerURLArg()...)
		args = append(args, vcIssuerURLArg()...)
		args = append(args, comparatorURLArg()...)
		args = append(args, hostExternalURLArg()...)
		args = append(args, accountLinkProfileArg()...)
		args = append(args, []string{flag + common.DatabasePrefixFlagName, "test"}...)
		args = append(args, []string{flag + common.DatabaseURLFlagName, "invalid-driver://test"}...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(), "unsupported storage driver: invalid-driver")
	})
}

func TestVaultServerArg(t *testing.T) {
	t.Run("missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		args = append(args, demoModeArg("rev")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither vault-server-url (command line flag) nor ACRP_VAULT_SERVER_URL (environment variable) have been set.")
	})
}

func TestComparatorURLArg(t *testing.T) {
	t.Run("missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		args = append(args, demoModeArg("rev")...)
		args = append(args, vaultServerURLArg()...)
		args = append(args, vcIssuerURLArg()...)
		args = append(args, hostExternalURLArg()...)
		args = append(args, accountLinkProfileArg()...)

		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither comparator-url (command line flag) nor ACRP_COMPARATOR_URL (environment variable) have been set.")
	})
}

func TestVCIssuerArg(t *testing.T) {
	t.Run("missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		args = append(args, demoModeArg("rev")...)
		args = append(args, vaultServerURLArg()...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither vc-issuer-url (command line flag) nor ACRP_VC_ISSUER_URL (environment variable) have been set.")
	})
}

func TestHostExternalURLArg(t *testing.T) {
	t.Run("missing arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args, tlsCertFileArg()...)
		args = append(args, tlsKeyFileArg()...)
		args = append(args, databaseURLArg()...)
		args = append(args, databasePrefixArg()...)
		args = append(args, demoModeArg("rev")...)
		args = append(args, vaultServerURLArg()...)
		args = append(args, vcIssuerURLArg()...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Contains(t, err.Error(),
			"Neither host-external-url (command line flag) nor ACRP_HOST_EXTERNAL_URL (environment variable) have been set.")
	})
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

func TestTStaticPaths(t *testing.T) {
	router := pathPrefix("static")

	tests := []struct {
		url string
	}{
		{"/showlogin"},
		{"/showregister"},
	}

	for _, tt := range tests {
		rr, err := http.NewRequest("GET", tt.url, nil)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		router.ServeHTTP(w, rr)
		require.Equal(t, http.StatusNotFound, w.Code, "failed for url=%s", tt.url)
	}
}

func setEnvVars(t *testing.T) {
	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)

	err = os.Setenv(demoModeEnvKey, "rev")
	require.Nil(t, err)

	err = os.Setenv(tlsCertFileEnvKey, "cert")
	require.Nil(t, err)

	err = os.Setenv(tlsKeyFileEnvKey, "key")
	require.Nil(t, err)

	err = os.Setenv(common.DatabaseURLEnvKey, "mem://test")
	require.NoError(t, err)

	err = os.Setenv(common.DatabasePrefixEnvKey, "test")
	require.NoError(t, err)

	err = os.Setenv(vaultServerURLEnvKey, "https://vault-server")
	require.Nil(t, err)

	err = os.Setenv(vcIssuerURLEnvKey, "https://vc-issuer-server")
	require.Nil(t, err)

	err = os.Setenv(hostExternalURLEnvKey, "https://my-external-url")
	require.Nil(t, err)

	err = os.Setenv(accountLinkProfileEnvKey, "profile-test")
	require.Nil(t, err)

	err = os.Setenv(comparatorURLEnvKey, "https://comparator")
	require.Nil(t, err)
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

	err = os.Unsetenv(demoModeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(vaultServerURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(vcIssuerURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(hostExternalURLEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(accountLinkProfileEnvKey)
	require.Nil(t, err)

	err = os.Unsetenv(comparatorURLEnvKey)
	require.Nil(t, err)
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

func logLevelArg(logLevel string) []string {
	return []string{flag + common.LogLevelFlagName, logLevel}
}

func demoModeArg(mode string) []string {
	return []string{flag + demoModeFlagName, mode}
}

func vaultServerURLArg() []string {
	return []string{flag + vaultServerURLFlagName, "https://vault-server"}
}

func comparatorURLArg() []string {
	return []string{flag + comparatorURLFlagName, "https://comparator"}
}

func vcIssuerURLArg() []string {
	return []string{flag + vcIssuerURLFlagName, "https://vc-issuer-server"}
}

func hostExternalURLArg() []string {
	return []string{flag + hostExternalURLFlagName, "https://my-external-url"}
}

func accountLinkProfileArg() []string {
	return []string{flag + accountLinkProfileFlagName, "profile-abc"}
}

func databaseURLArg() []string {
	return []string{flag + common.DatabaseURLFlagName, "mem://test"}
}

func databasePrefixArg() []string {
	return []string{flag + common.DatabasePrefixFlagName, "database-prefix"}
}

func requestTokensArg() []string {
	return []string{flag + requestTokensFlagName, "token1=tk1", flag + requestTokensFlagName, "token2=tk2=tk2"}
}
