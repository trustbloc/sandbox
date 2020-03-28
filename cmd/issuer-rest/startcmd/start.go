/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer/operation"
	tokenIssuer "github.com/trustbloc/edge-sandbox/pkg/token/issuer"
	tokenResolver "github.com/trustbloc/edge-sandbox/pkg/token/resolver"
	cmdutils "github.com/trustbloc/edge-sandbox/pkg/utils/cmd"
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
)

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	return http.ListenAndServeTLS(host, certFile, keyFile, router)
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
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start issuer",
		Long:  "Start issuer",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			oauth2Config, err := getOAuth2Config(cmd)
			if err != nil {
				return err
			}

			tokenIntrospectionURL, err := cmdutils.GetUserSetVar(cmd, introspectionURLFlagName, introspectionURLEnvKey, false)
			if err != nil {
				return err
			}

			tlsCertFile, err := cmdutils.GetUserSetVar(cmd, tlsCertFileFlagName, tlsCertFileEnvKey, false)
			if err != nil {
				return err
			}

			tlsKeyFile, err := cmdutils.GetUserSetVar(cmd, tlsKeyFileFlagName, tlsKeyFileEnvKey, false)
			if err != nil {
				return err
			}

			cmsURL, err := cmdutils.GetUserSetVar(cmd, cmsURLFlagName, cmsURLEnvKey, false)
			if err != nil {
				return err
			}

			vcsURL, err := cmdutils.GetUserSetVar(cmd, vcsURLFlagName, vcsURLEnvKey, false)
			if err != nil {
				return err
			}

			parameters := &issuerParameters{
				srv:                   srv,
				hostURL:               strings.TrimSpace(hostURL),
				oauth2Config:          oauth2Config,
				tokenIntrospectionURL: strings.TrimSpace(tokenIntrospectionURL),
				tlsCertFile:           tlsCertFile,
				tlsKeyFile:            tlsKeyFile,
				cmsURL:                strings.TrimSpace(cmsURL),
				vcsURL:                strings.TrimSpace(vcsURL),
			}

			return startIssuer(parameters)
		},
	}
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
}

func startIssuer(parameters *issuerParameters) error {
	cfg := &operation.Config{
		TokenIssuer:   tokenIssuer.New(parameters.oauth2Config),
		TokenResolver: tokenResolver.New(parameters.tokenIntrospectionURL),
		CMSURL:        parameters.cmsURL,
		VCSURL:        parameters.vcsURL,
		QRCodeHTML:    "static/qr.html",
		ReceiveVCHTML: "static/receiveVC.html",
		VCHTML:        "static/vc.html"}

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

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, parameters.tlsCertFile, parameters.tlsKeyFile, router)
}

func getOAuth2Config(cmd *cobra.Command) (*oauth2.Config, error) {
	authURL, err := cmdutils.GetUserSetVar(cmd, endpointAuthURLFlagName, endpointAuthURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tokenURL, err := cmdutils.GetUserSetVar(cmd, endpointTokenURLFlagName, endpointTokenURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	hydra := oauth2.Endpoint{
		AuthURL:   strings.TrimSpace(authURL),
		TokenURL:  strings.TrimSpace(tokenURL),
		AuthStyle: 2, // basic
	}

	redirectURL, err := cmdutils.GetUserSetVar(cmd, clientRedirectURLFlagName, clientRedirectURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	clientID, err := cmdutils.GetUserSetVar(cmd, clientIDFlagName, clientIDEnvKey, false)
	if err != nil {
		return nil, err
	}

	secret, err := cmdutils.GetUserSetVar(cmd, clientSecretFlagName, clientSecretEnvKey, false)
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
