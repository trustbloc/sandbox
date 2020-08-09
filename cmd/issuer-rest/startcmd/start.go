/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/cmd/common"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer/operation"
	tokenIssuer "github.com/trustbloc/edge-sandbox/pkg/token/issuer"
	tokenResolver "github.com/trustbloc/edge-sandbox/pkg/token/resolver"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the issuer instance on. Format: HostName:Port."
	hostURLEnvKey        = "ISSUER_HOST_URL"

	// oauth2 endpoint config flags
	endpointAuthURLFlagName      = "auth-url"
	endpointAuthURLFlagShorthand = "a"
	endpointAuthURLFlagUsage     = "Auth URL for auth2 server. Format: HostName:Port."
	endpointAuthURLEnvKey        = "OAUTH2_ENDPOINT_AUTH_URL"

	endpointTokenURLFlagName      = "token-url"
	endpointTokenURLFlagShorthand = "t"
	endpointTokenURLFlagUsage     = "Token URL for auth2 server. Format: HostName:Port." // #nosec
	endpointTokenURLEnvKey        = "OAUTH2_ENDPOINT_TOKEN_URL"                          // #nosec

	// oauth2 client config flags
	clientRedirectURLFlagName      = "redirect-url"
	clientRedirectURLFlagShorthand = "r"
	clientRedirectURLFlagUsage     = "Redirect URL for auth2 client. Format: HostName:Port."
	clientRedirectURLEnvKey        = "OAUTH2_ISSUER_CLIENT_REDIRECT_URL"

	clientIDFlagName      = "client-id"
	clientIDFlagShorthand = "c"
	clientIDFlagUsage     = "Client ID for issuer auth2 client."
	clientIDEnvKey        = "OAUTH2_ISSUER_CLIENT_ID"

	clientSecretFlagName      = "client-secret"
	clientSecretFlagShorthand = "s"
	clientSecretFlagUsage     = "Client secret for issuer auth2 client."
	clientSecretEnvKey        = "OAUTH2_ISSUER_CLIENT_SECRET" // #nosec

	// oauth2 token introspection config flags
	introspectionURLFlagName      = "introspect-url"
	introspectionURLFlagShorthand = "i"
	introspectionURLFlagUsage     = "Token introspection URL for auth2 server. Format: HostName:Port."
	introspectionURLEnvKey        = "OAUTH2_ENDPOINT_TOKEN_INTROSPECTION_URL"

	tlsCertFileFlagName      = "tls-cert-file"
	tlsCertFileFlagShorthand = ""
	tlsCertFileFlagUsage     = "tls certificate file." +
		" Alternatively, this can be set with the following environment variable: " + tlsCertFileEnvKey
	tlsCertFileEnvKey = "ISSUER_TLS_CERT_FILE"

	tlsKeyFileFlagName      = "tls-key-file"
	tlsKeyFileFlagShorthand = ""
	tlsKeyFileFlagUsage     = "tls key file." +
		" Alternatively, this can be set with the following environment variable: " + tlsKeyFileEnvKey
	tlsKeyFileEnvKey = "ISSUER_TLS_KEY_FILE"

	// content management url config flags
	cmsURLFlagName      = "cms-url"
	cmsURLFlagShorthand = "m"
	cmsURLFlagUsage     = "Content management server (CMS) URL. Format: HostName:Port."
	cmsURLEnvKey        = "ISSUER_CMS_URL"

	// vc service url config flags
	vcsURLFlagName      = "vcs-url"
	vcsURLFlagShorthand = "v"
	vcsURLFlagUsage     = "VC Service URL. Format: HostName:Port."
	vcsURLEnvKey        = "ISSUER_VCS_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ISSUER_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ISSUER_TLS_CACERTS"

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "ISSUER_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request " +
		" Alternatively, this can be set with the following environment variable: " + requestTokensEnvKey

	databaseTypeFlagName  = "database-type"
	databaseTypeEnvKey    = "DATABASE_TYPE"
	databaseTypeFlagUsage = "The type of database to use for everything except key storage. " +
		"Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: " +
		databaseTypeEnvKey

	databaseURLFlagName  = "database-url"
	databaseURLEnvKey    = "DATABASE_URL"
	databaseURLFlagUsage = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required. Alternatively, this " +
		"can be set with the following environment variable: " + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		"Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	// issuer adapter url
	issuerAdapterURLFlagName  = "issuer-adapter-url"
	issuerAdapterURLFlagUsage = "Issuer Adapter Service URL. Format: HostName:Port."
	issuerAdapterURLEnvKey    = "ISSUER_ADAPTER_URL"
)

const (
	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
)

var logger = log.New("issuer-rest")

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

type issuerParameters struct {
	srv                   server
	hostURL               string
	oauth2Config          *oauth2.Config
	tokenIntrospectionURL string
	tlsCertFile           string
	tlsKeyFile            string
	cmsURL                string
	vcsURL                string
	tlsSystemCertPool     bool
	tlsCACerts            []string
	requestTokens         map[string]string
	issuerAdapterURL      string
	logLevel              string
	dbParameters          *dbParameters
}

type tlsConfig struct {
	certFile       string
	keyFile        string
	systemCertPool bool
	caCerts        []string
}

type dbParameters struct {
	databaseType   string
	databaseURL    string
	databasePrefix string
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

// nolint: funlen
func createStartCmd(srv server) *cobra.Command { // nolint: gocyclo
	return &cobra.Command{
		Use:   "start",
		Short: "Start issuer",
		Long:  "Start issuer",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			oauth2Config, err := getOAuth2Config(cmd)
			if err != nil {
				return err
			}

			tokenIntrospectionURL, err := cmdutils.GetUserSetVarFromString(cmd, introspectionURLFlagName,
				introspectionURLEnvKey, false)
			if err != nil {
				return err
			}

			cmsURL, err := cmdutils.GetUserSetVarFromString(cmd, cmsURLFlagName, cmsURLEnvKey, false)
			if err != nil {
				return err
			}

			vcsURL, err := cmdutils.GetUserSetVarFromString(cmd, vcsURLFlagName, vcsURLEnvKey, false)
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

			issuerAdapterURL, err := cmdutils.GetUserSetVarFromString(cmd, issuerAdapterURLFlagName,
				issuerAdapterURLEnvKey, false)
			if err != nil {
				return err
			}

			loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey, true)
			if err != nil {
				return err
			}

			dbParams, err := getDBParameters(cmd)
			if err != nil {
				return err
			}

			parameters := &issuerParameters{
				srv:                   srv,
				hostURL:               strings.TrimSpace(hostURL),
				oauth2Config:          oauth2Config,
				tokenIntrospectionURL: strings.TrimSpace(tokenIntrospectionURL),
				tlsCertFile:           tlsConfg.certFile,
				tlsKeyFile:            tlsConfg.keyFile,
				cmsURL:                strings.TrimSpace(cmsURL),
				vcsURL:                strings.TrimSpace(vcsURL),
				tlsSystemCertPool:     tlsConfg.systemCertPool,
				tlsCACerts:            tlsConfg.caCerts,
				requestTokens:         requestTokens,
				issuerAdapterURL:      issuerAdapterURL,
				logLevel:              loggingLevel,
				dbParameters:          dbParams,
			}

			return startIssuer(parameters)
		},
	}
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
		case 2:
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
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(endpointAuthURLFlagName, endpointAuthURLFlagShorthand, "", endpointAuthURLFlagUsage)
	startCmd.Flags().StringP(endpointTokenURLFlagName, endpointTokenURLFlagShorthand, "", endpointTokenURLFlagUsage)
	startCmd.Flags().StringP(clientRedirectURLFlagName, clientRedirectURLFlagShorthand, "", clientRedirectURLFlagUsage)
	startCmd.Flags().StringP(clientIDFlagName, clientIDFlagShorthand, "", clientIDFlagUsage)
	startCmd.Flags().StringP(clientSecretFlagName, clientSecretFlagShorthand, "", clientSecretFlagUsage)
	startCmd.Flags().StringP(introspectionURLFlagName, introspectionURLFlagShorthand, "",
		introspectionURLFlagUsage)
	startCmd.Flags().StringP(tlsCertFileFlagName, tlsCertFileFlagShorthand, "", tlsCertFileFlagUsage)
	startCmd.Flags().StringP(tlsKeyFileFlagName, tlsKeyFileFlagShorthand, "", tlsKeyFileFlagUsage)
	startCmd.Flags().StringP(cmsURLFlagName, cmsURLFlagShorthand, "", cmsURLFlagUsage)
	startCmd.Flags().StringP(vcsURLFlagName, vcsURLFlagShorthand, "", vcsURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringArrayP(requestTokensFlagName, "", []string{}, requestTokensFlagUsage)

	// db
	startCmd.Flags().StringP(databaseTypeFlagName, "", "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, "", "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)

	// did-comm
	startCmd.Flags().StringP(issuerAdapterURLFlagName, "", "", issuerAdapterURLFlagUsage)

	// default log level
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
}

func startIssuer(parameters *issuerParameters) error { //nolint:funlen
	if parameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, parameters.logLevel)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs}

	storeProvider, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	cfg := &operation.Config{
		TokenIssuer:      tokenIssuer.New(parameters.oauth2Config, tokenIssuer.WithTLSConfig(tlsConfig)),
		TokenResolver:    tokenResolver.New(parameters.tokenIntrospectionURL, tokenResolver.WithTLSConfig(tlsConfig)),
		CMSURL:           parameters.cmsURL,
		VCSURL:           parameters.vcsURL,
		DIDAuthHTML:      "static/didAuth.html",
		ReceiveVCHTML:    "static/receiveVC.html",
		VCHTML:           "static/vc.html",
		DIDCommHTML:      "static/didcomm.html",
		TLSConfig:        tlsConfig,
		RequestTokens:    parameters.requestTokens,
		IssuerAdapterURL: parameters.issuerAdapterURL,
		StoreProvider:    storeProvider,
	}

	issuerService, err := issuer.New(cfg)
	if err != nil {
		return err
	}

	handlers := issuerService.GetOperations()
	router := mux.NewRouter()

	fs := http.FileServer(http.Dir("static"))

	router.PathPrefix("/reader/").Handler(fs)
	router.PathPrefix("/view/").Handler(fs)
	router.PathPrefix("/css/").Handler(fs)
	router.PathPrefix("/img/").Handler(fs)
	router.PathPrefix("/js/").Handler(fs)

	router.Handle("/", fs)
	router.PathPrefix("/drivinglicense").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/drivinglicense.html")
	})

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, parameters.tlsCertFile, parameters.tlsKeyFile, router)
}

func getOAuth2Config(cmd *cobra.Command) (*oauth2.Config, error) {
	authURL, err := cmdutils.GetUserSetVarFromString(cmd, endpointAuthURLFlagName, endpointAuthURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tokenURL, err := cmdutils.GetUserSetVarFromString(cmd, endpointTokenURLFlagName, endpointTokenURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	hydra := oauth2.Endpoint{
		AuthURL:   strings.TrimSpace(authURL),
		TokenURL:  strings.TrimSpace(tokenURL),
		AuthStyle: 2, // basic
	}

	redirectURL, err := cmdutils.GetUserSetVarFromString(cmd, clientRedirectURLFlagName, clientRedirectURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	clientID, err := cmdutils.GetUserSetVarFromString(cmd, clientIDFlagName, clientIDEnvKey, false)
	if err != nil {
		return nil, err
	}

	secret, err := cmdutils.GetUserSetVarFromString(cmd, clientSecretFlagName, clientSecretEnvKey, false)
	if err != nil {
		return nil, err
	}

	config := &oauth2.Config{
		RedirectURL:  strings.TrimSpace(redirectURL),
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(secret),
		Endpoint:     hydra,
	}

	return config, nil
}

func getDBParameters(cmd *cobra.Command) (*dbParameters, error) {
	databaseType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName,
		databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	databaseURL, err := cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName,
		databaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName,
		databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &dbParameters{
		databaseType:   databaseType,
		databaseURL:    databaseURL,
		databasePrefix: databasePrefix,
	}, nil
}

func createStoreProviders(parameters *issuerParameters) (storage.Provider, error) {
	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		return memstore.NewProvider(), nil
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		return couchdbstore.NewProvider(parameters.dbParameters.databaseURL,
			couchdbstore.WithDBPrefix(parameters.dbParameters.databasePrefix))
	}

	return nil, fmt.Errorf("database type '%s' is invalid", parameters.dbParameters.databaseType)
}
