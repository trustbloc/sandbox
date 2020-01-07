/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"

	"github.com/trustbloc/edge-sandbox/pkg/restapi/issuer"
	cmdutils "github.com/trustbloc/edge-sandbox/pkg/utils/cmd"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the issuer instance on. Format: HostName:Port."
	hostURLEnvKey        = "ISSUER_HOST_URL"
)

var errMissingHostURL = errors.New("host URL not provided")

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
	srv     server
	hostURL string
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
			parameters := &issuerParameters{
				srv:     srv,
				hostURL: hostURL,
			}
			return startIssuer(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
}

func startIssuer(parameters *issuerParameters) error {
	if parameters.hostURL == "" {
		return errMissingHostURL
	}

	issuerService, err := issuer.New()
	if err != nil {
		return err
	}

	handlers := issuerService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	err = parameters.srv.ListenAndServe(parameters.hostURL, router)

	return err
}
