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

	"github.com/trustbloc/edge-sandbox/pkg/restapi/rp"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/rp/operation"
	cmdutils "github.com/trustbloc/edge-sandbox/pkg/utils/cmd"
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

type rpParameters struct {
	srv          server
	hostURL      string
	tlsCertFile  string
	tlsKeyFile   string
	vcServiceURL string
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
		Short: "Start rp",
		Long:  "Start rp",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
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

			vcServiceURL, err := cmdutils.GetUserSetVar(cmd, vcsURLFlagName, vcsURLEnvKey, false)
			if err != nil {
				return err
			}

			parameters := &rpParameters{
				srv:          srv,
				hostURL:      strings.TrimSpace(hostURL),
				tlsCertFile:  tlsCertFile,
				tlsKeyFile:   tlsKeyFile,
				vcServiceURL: vcServiceURL,
			}

			return startRP(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsCertFileFlagName, "", "", tlsCertFileFlagUsage)
	startCmd.Flags().StringP(tlsKeyFileFlagName, "", "", tlsKeyFileFlagUsage)
	startCmd.Flags().StringP(vcsURLFlagName, "", "", vcsURLFlagUsage)
}

func startRP(parameters *rpParameters) error {
	cfg := &operation.Config{
		VCHTML: "static/vc.html",
		VPHTML: "static/vp.html",
		VCSURL: parameters.vcServiceURL}

	rpService, err := rp.New(cfg)
	if err != nil {
		return err
	}

	handlers := rpService.GetOperations()
	router := mux.NewRouter()

	fs := http.FileServer(http.Dir("static"))
	router.PathPrefix("/reader/").Handler(fs)
	router.PathPrefix("/css/").Handler(fs)
	router.PathPrefix("/img/").Handler(fs)
	router.PathPrefix("/js/").Handler(fs)

	router.Handle("/", fs)

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, parameters.tlsCertFile, parameters.tlsKeyFile, router)
}
