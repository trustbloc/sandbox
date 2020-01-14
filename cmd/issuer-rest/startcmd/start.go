/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer/operation"
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

	clientScopesFlagName      = "client-scopes"
	clientScopesFlagShorthand = "p"
	clientScopesFlagUsage     = "Client scopes for issuer auth2 client."
	clientScopesEnvKey        = "OAUTH2_ISSUER_CLIENT_SCOPES"
)

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

type issuerParameters struct {
	srv          server
	hostURL      string
	oauth2Config *oauth2.Config
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
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey)
			if err != nil {
				return err
			}

			oauth2Config, err := getOAuth2Config(cmd)
			if err != nil {
				return err
			}

			parameters := &issuerParameters{
				srv:          srv,
				hostURL:      strings.TrimSpace(hostURL),
				oauth2Config: oauth2Config,
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
	startCmd.Flags().StringP(clientScopesFlagName, clientScopesFlagShorthand, "", clientScopesFlagUsage)
}

func startIssuer(parameters *issuerParameters) error {
	if parameters.hostURL == "" {
		return errors.New("host URL is empty")
	}

	if err := validateOAuth2Config(parameters.oauth2Config); err != nil {
		return err
	}

	cfg := &operation.Config{OAuth2Config: parameters.oauth2Config}

	issuerService, err := issuer.New(cfg)
	if err != nil {
		return err
	}

	handlers := issuerService.GetOperations()
	router := mux.NewRouter()

	router.Handle("/", http.FileServer(http.Dir("static")))

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, router)
}

func getOAuth2Config(cmd *cobra.Command) (*oauth2.Config, error) {
	authURL, err := cmdutils.GetUserSetVar(cmd, endpointAuthURLFlagName, endpointAuthURLEnvKey)
	if err != nil {
		return nil, err
	}

	tokenURL, err := cmdutils.GetUserSetVar(cmd, endpointTokenURLFlagName, endpointTokenURLEnvKey)
	if err != nil {
		return nil, err
	}

	hydra := oauth2.Endpoint{
		AuthURL:   strings.TrimSpace(authURL),
		TokenURL:  strings.TrimSpace(tokenURL),
		AuthStyle: 2, // basic
	}

	redirectURL, err := cmdutils.GetUserSetVar(cmd, clientRedirectURLFlagName, clientRedirectURLEnvKey)
	if err != nil {
		return nil, err
	}

	clientID, err := cmdutils.GetUserSetVar(cmd, clientIDFlagName, clientIDEnvKey)
	if err != nil {
		return nil, err
	}

	secret, err := cmdutils.GetUserSetVar(cmd, clientSecretFlagName, clientSecretEnvKey)
	if err != nil {
		return nil, err
	}

	scopes, err := cmdutils.GetUserSetVar(cmd, clientScopesFlagName, clientScopesEnvKey)
	if err != nil {
		return nil, err
	}

	config := &oauth2.Config{
		RedirectURL:  strings.TrimSpace(redirectURL),
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(secret),
		Scopes:       strings.Split(strings.TrimSpace(scopes), ","),
		Endpoint:     hydra,
	}

	return config, nil
}

func validateOAuth2Config(config *oauth2.Config) error {
	if config.Endpoint.AuthURL == "" {
		return errors.New("auth URL is empty")
	}

	if config.Endpoint.TokenURL == "" {
		return errors.New("token URL is empty")
	}

	if config.RedirectURL == "" {
		return errors.New("redirect URL is empty")
	}

	if config.ClientID == "" {
		return errors.New("client ID is empty")
	}

	if config.ClientSecret == "" {
		return errors.New("secret is empty")
	}

	if len(config.Scopes) == 0 {
		return errors.New("scopes is empty")
	}

	return nil
}
