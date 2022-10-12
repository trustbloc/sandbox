/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/sandbox/cmd/common"
	"github.com/trustbloc/sandbox/pkg/restapi/healthcheck"
	"github.com/trustbloc/sandbox/pkg/restapi/rp"
	"github.com/trustbloc/sandbox/pkg/restapi/rp/operation"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the rp instance on. Format: HostName:Port."
	hostURLEnvKey        = "RP_HOST_URL"

	tlsCertFileFlagName  = "tls-cert-file"
	tlsCertFileFlagUsage = "tls certificate file." +
		" Alternatively, this can be set with the following environment variable: " + tlsCertFileEnvKey
	tlsCertFileEnvKey = "RP_TLS_CERT_FILE"

	tlsKeyFileFlagName  = "tls-key-file"
	tlsKeyFileFlagUsage = "tls key file." +
		" Alternatively, this can be set with the following environment variable: " + tlsKeyFileEnvKey
	tlsKeyFileEnvKey = "RP_TLS_KEY_FILE"

	// vc service url config flags
	vcsURLFlagName  = "vcs-url"
	vcsURLFlagUsage = "VC Service URL. Format: HostName:Port."
	vcsURLEnvKey    = "RP_VCS_URL"

	// vc v1 service url config flags
	vcsV1URLFlagName  = "vcs-v1-url"
	vcsV1URLFlagUsage = "VC Service URL V1. Format: HostName:Port." +
		" Alternatively, this can be set with the following environment variable: " + vcsV1URLEnvKey
	vcsV1URLEnvKey = "RP_VCS_V1_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "RP_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "RP_TLS_CACERTS"

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "RP_REQUEST_TOKENS"
	requestTokensFlagUsage = "Tokens used for http request " +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey

	// OIDC flags
	oidcProviderURLFlagName  = "oidc-opurl"
	oidcProviderURLFlagUsage = "URL for the OIDC provider." +
		" Alternatively, this can be set with the following environment variable: " + oidcProviderURLEnvKey
	oidcProviderURLEnvKey = "RP_OIDC_OPURL"

	oidcClientIDFlagName  = "oidc-clientid"
	oidcClientIDFlagUsage = "OAuth2 client_id for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + oidcProviderURLEnvKey
	oidcClientIDEnvKey = "RP_OIDC_CLIENTID"

	oidcClientSecretFlagName  = "oidc-clientsecret" //nolint:gosec
	oidcClientSecretFlagUsage = "OAuth2 client secret for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + oidcClientSecretEnvKey
	oidcClientSecretEnvKey = "RP_OIDC_CLIENTSECRET" //nolint:gosec

	oidcCallbackURLFlagName  = "oidc-callback"
	oidcCallbackURLFlagUsage = "Base URL for the OAuth2 callback endpoints." +
		" Alternatively, this can be set with the following environment variable: " + oidcCallbackURLEnvKey
	oidcCallbackURLEnvKey = "RP_OIDC_CALLBACK"

	// OIDC flags
	waciOIDCProviderURLFlagName  = "waci-oidc-opurl"
	waciOIDCProviderURLFlagUsage = "URL for the OIDC provider." +
		" Alternatively, this can be set with the following environment variable: " + waciOIDCProviderURLEnvKey
	waciOIDCProviderURLEnvKey = "RP_WACI_OIDC_OPURL"

	waciOIDCClientIDFlagName  = "waci-oidc-clientid"
	waciOIDCClientIDFlagUsage = "OAuth2 client_id for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + waciOIDCClientIDEnvKey
	waciOIDCClientIDEnvKey = "RP_WACI_OIDC_CLIENTID"

	waciOIDCClientSecretFlagName  = "waci-oidc-clientsecret" //nolint:gosec
	waciOIDCClientSecretFlagUsage = "OAuth2 client secret for OIDC." +
		" Alternatively, this can be set with the following environment variable: " + waciOIDCClientSecretEnvKey
	waciOIDCClientSecretEnvKey = "RP_WACI_OIDC_CLIENTSECRET" //nolint:gosec

	waciOIDCCallbackURLFlagName  = "waci-oidc-callback"
	waciOIDCCallbackURLFlagUsage = "Base URL for the OAuth2 callback endpoints." +
		" Alternatively, this can be set with the following environment variable: " + waciOIDCCallbackURLEnvKey
	waciOIDCCallbackURLEnvKey = "RP_WACI_OIDC_CALLBACK"

	walletAuthURLFlagName  = "wallet-auth-url"
	walletAuthURLFlagUsage = "Wallet auth URL for rp oidc share" +
		" Alternatively, this can be set with the following environment variable: " + walletAuthURLEnvKey
	walletAuthURLEnvKey = "RP_WALLET_AUTH_URL"

	accessTokenURLFlagName  = "access-token-url"
	accessTokenURLFlagUsage = "Access token url" +
		" Alternatively, this can be set with the following environment variable: " + accessTokenURLEnvKey
	accessTokenURLEnvKey = "RP_ACCESS_TOKEN_URL"

	apiGatewayURLFlagName  = "api-gateway-url"
	apiGatewayURLFlagUsage = "Api gateway url" +
		" Alternatively, this can be set with the following environment variable: " + apiGatewayURLEnvKey
	apiGatewayURLEnvKey = "RP_API_GATEWAY_URL"

	tokenLength2 = 2
)

var logger = log.New("rp-rest")

var getOIDCParametersFunc = getOIDCParameters // nolint: gochecknoglobals

var getWACIOIDCParametersFunc = getWACIOIDCParameters // nolint: gochecknoglobals

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

type rpParameters struct {
	srv                server
	hostURL            string
	tlsCertFile        string
	tlsKeyFile         string
	vcServiceURL       string
	vcV1ServiceURL     string
	tlsSystemCertPool  bool
	tlsCACerts         []string
	requestTokens      map[string]string
	logLevel           string
	oidcParameters     *oidcParameters
	waciOIDCParameters *oidcParameters
	walletAuthURL      string
	dbParams           *common.DBParameters
	accessTokenURL     string
	apiGatewayURL      string
}

type oidcParameters struct {
	oidcProviderURL  string
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
}

type tlsConfig struct {
	certFile       string
	keyFile        string
	systemCertPool bool
	caCerts        []string
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command { // nolint: funlen,gocyclo
	return &cobra.Command{
		Use:   "start",
		Short: "Start rp",
		Long:  "Start rp",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			vcServiceURL, err := cmdutils.GetUserSetVarFromString(cmd, vcsURLFlagName, vcsURLEnvKey, false)
			if err != nil {
				return err
			}

			vcV1ServiceURL, err := cmdutils.GetUserSetVarFromString(cmd, vcsV1URLFlagName, vcsV1URLEnvKey, false)
			if err != nil {
				return err
			}

			tlsConfg, err := getTLS(cmd)
			if err != nil {
				return err
			}

			requestTokens, err := getRequestTokens(cmd)
			if err != nil {
				return err
			}

			loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey, true)
			if err != nil {
				return err
			}

			oidcParams, err := getOIDCParametersFunc(cmd)
			if err != nil {
				return err
			}

			waciOIDCParams, err := getWACIOIDCParametersFunc(cmd)
			if err != nil {
				return err
			}

			dbParams, err := common.DBParams(cmd)
			if err != nil {
				return err
			}

			walletAuthURL, err := cmdutils.GetUserSetVarFromString(cmd, walletAuthURLFlagName, walletAuthURLEnvKey, true)
			if err != nil {
				return err
			}

			accessTokenURL := cmdutils.GetUserSetOptionalVarFromString(cmd, accessTokenURLFlagName, accessTokenURLEnvKey)

			apiGatewayURL := cmdutils.GetUserSetOptionalVarFromString(cmd, apiGatewayURLFlagName, apiGatewayURLEnvKey)

			parameters := &rpParameters{
				srv:                srv,
				hostURL:            strings.TrimSpace(hostURL),
				tlsCertFile:        tlsConfg.certFile,
				tlsKeyFile:         tlsConfg.keyFile,
				vcServiceURL:       vcServiceURL,
				vcV1ServiceURL:     vcV1ServiceURL,
				tlsSystemCertPool:  tlsConfg.systemCertPool,
				tlsCACerts:         tlsConfg.caCerts,
				requestTokens:      requestTokens,
				logLevel:           loggingLevel,
				oidcParameters:     oidcParams,
				waciOIDCParameters: waciOIDCParams,
				walletAuthURL:      walletAuthURL,
				dbParams:           dbParams,
				accessTokenURL:     accessTokenURL,
				apiGatewayURL:      apiGatewayURL,
			}

			return startRP(parameters)
		},
	}
}

// nolint: dupl
func getOIDCParameters(cmd *cobra.Command) (*oidcParameters, error) {
	oidcProviderURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcProviderURLFlagName, oidcProviderURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientID, err := cmdutils.GetUserSetVarFromString(cmd, oidcClientIDFlagName, oidcClientIDEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientSecret, err := cmdutils.GetUserSetVarFromString(
		cmd, oidcClientSecretFlagName, oidcClientSecretEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcCallbackURL, err := cmdutils.GetUserSetVarFromString(cmd, oidcCallbackURLFlagName, oidcCallbackURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &oidcParameters{
		oidcProviderURL:  oidcProviderURL,
		oidcClientID:     oidcClientID,
		oidcClientSecret: oidcClientSecret,
		oidcCallbackURL:  oidcCallbackURL,
	}, nil
}

// nolint: dupl
func getWACIOIDCParameters(cmd *cobra.Command) (*oidcParameters, error) {
	oidcProviderURL, err := cmdutils.GetUserSetVarFromString(cmd, waciOIDCProviderURLFlagName,
		waciOIDCProviderURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientID, err := cmdutils.GetUserSetVarFromString(cmd, waciOIDCClientIDFlagName, waciOIDCClientIDEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcClientSecret, err := cmdutils.GetUserSetVarFromString(
		cmd, waciOIDCClientSecretFlagName, waciOIDCClientSecretEnvKey, true)
	if err != nil {
		return nil, err
	}

	oidcCallbackURL, err := cmdutils.GetUserSetVarFromString(cmd, waciOIDCCallbackURLFlagName,
		waciOIDCCallbackURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &oidcParameters{
		oidcProviderURL:  oidcProviderURL,
		oidcClientID:     oidcClientID,
		oidcClientSecret: oidcClientSecret,
		oidcCallbackURL:  oidcCallbackURL,
	}, nil
}

func getRequestTokens(cmd *cobra.Command) (map[string]string, error) {
	requestTokens, err := cmdutils.GetUserSetVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey, true)
	if err != nil {
		return nil, err
	}

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case tokenLength2:
			tokens[split[0]] = split[1]
		default:
			logger.Warnf("invalid token '%s'", token)
		}
	}

	return tokens, nil
}

func getTLS(cmd *cobra.Command) (*tlsConfig, error) {
	tlsCertFile, err := cmdutils.GetUserSetVarFromString(cmd, tlsCertFileFlagName,
		tlsCertFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsKeyFile, err := cmdutils.GetUserSetVarFromString(cmd, tlsKeyFileFlagName,
		tlsKeyFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &tlsConfig{certFile: tlsCertFile,
		keyFile: tlsKeyFile, systemCertPool: tlsSystemCertPool, caCerts: tlsCACerts}, nil
}

func createFlags(startCmd *cobra.Command) {
	common.Flags(startCmd)
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsCertFileFlagName, "", "", tlsCertFileFlagUsage)
	startCmd.Flags().StringP(tlsKeyFileFlagName, "", "", tlsKeyFileFlagUsage)
	startCmd.Flags().StringP(vcsURLFlagName, "", "", vcsURLFlagUsage)
	startCmd.Flags().StringP(vcsV1URLFlagName, "", "", vcsV1URLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
	startCmd.Flags().StringP(oidcProviderURLFlagName, "", "", oidcProviderURLFlagUsage)
	startCmd.Flags().StringP(oidcClientIDFlagName, "", "", oidcClientIDFlagUsage)
	startCmd.Flags().StringP(oidcClientSecretFlagName, "", "", oidcClientSecretFlagUsage)
	startCmd.Flags().StringP(oidcCallbackURLFlagName, "", "", oidcCallbackURLFlagUsage)
	startCmd.Flags().StringP(waciOIDCProviderURLFlagName, "", "", waciOIDCProviderURLFlagUsage)
	startCmd.Flags().StringP(waciOIDCClientIDFlagName, "", "", waciOIDCClientIDFlagUsage)
	startCmd.Flags().StringP(waciOIDCClientSecretFlagName, "", "", waciOIDCClientSecretFlagUsage)
	startCmd.Flags().StringP(waciOIDCCallbackURLFlagName, "", "", waciOIDCCallbackURLFlagUsage)
	startCmd.Flags().StringP(walletAuthURLFlagName, "", "", walletAuthURLFlagUsage)
	startCmd.Flags().StringP(accessTokenURLFlagName, "", "", accessTokenURLFlagUsage)
	startCmd.Flags().StringP(apiGatewayURLFlagName, "", "", apiGatewayURLFlagUsage)
}

func startRP(parameters *rpParameters) error { //nolint:funlen
	if parameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, parameters.logLevel)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	transientStore, err := common.InitStore(parameters.dbParams, logger)
	if err != nil {
		return err
	}

	cfg := &operation.Config{
		VPHTML:                 "static/vp.html",
		DIDCOMMVPHTML:          "static/didcommvp.html",
		OIDCShareVPHTML:        "static/oidcvp.html",
		VCSURL:                 parameters.vcServiceURL,
		VCSV1URL:               parameters.vcV1ServiceURL,
		TLSConfig:              &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		RequestTokens:          parameters.requestTokens,
		TransientStoreProvider: transientStore,
		OIDCProviderURL:        parameters.oidcParameters.oidcProviderURL,
		OIDCClientID:           parameters.oidcParameters.oidcClientID,
		OIDCClientSecret:       parameters.oidcParameters.oidcClientSecret,
		OIDCCallbackURL:        parameters.oidcParameters.oidcCallbackURL,
		WACIOIDCProviderURL:    parameters.waciOIDCParameters.oidcProviderURL,
		WACIOIDCClientID:       parameters.waciOIDCParameters.oidcClientID,
		WACIOIDCClientSecret:   parameters.waciOIDCParameters.oidcClientSecret,
		WACIOIDCCallbackURL:    parameters.waciOIDCParameters.oidcCallbackURL,
		WalletAuthURL:          parameters.walletAuthURL,
		AccessTokenURL:         parameters.accessTokenURL,
		APIGatewayURL:          parameters.apiGatewayURL,
	}

	rpService, err := rp.New(cfg)
	if err != nil {
		return err
	}

	handlers := rpService.GetOperations()
	router := pathPrefix()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, parameters.tlsCertFile, parameters.tlsKeyFile, router)
}

func pathPrefix() *mux.Router {
	router := mux.NewRouter()

	fs := http.FileServer(http.Dir("static"))
	router.Handle("/", fs)
	router.PathPrefix("/img/").Handler(fs)

	router.PathPrefix("/bankaccount").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/bankaccount.html")
	})
	router.PathPrefix("/success").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/success.html")
	})
	router.PathPrefix("/flightcheckin").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/flightcheckin.html")
	})
	router.PathPrefix("/flightverify").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/flightcheckinverify.html")
	})
	router.PathPrefix("/demo").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/verifierdemo.html")
	})
	router.PathPrefix("/boardingpass").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/boardingpass.html")
	})
	router.PathPrefix("/creditsuccess").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/creditsuccess.html")
	})
	router.PathPrefix("/govsuccess").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/governmentsuccess.html")
	})
	router.PathPrefix("/government").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/government.html")
	})
	router.PathPrefix("/dutyfree").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/dutyfree.html")
	})
	router.PathPrefix("/prcsuccess").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/dutyfreesuccess.html")
	})
	router.PathPrefix("/backgroundcheck").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/backgroundcheck.html")
	})
	router.PathPrefix("/verifierqr").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/verifierqr.html")
	})

	return router
}
