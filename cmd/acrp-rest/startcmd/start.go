/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/edge-sandbox/cmd/common"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/acrp"
	"github.com/trustbloc/edge-sandbox/pkg/restapi/acrp/operation"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the rp instance on. Format: HostName:Port."
	hostURLEnvKey        = "ACRP_HOST_URL"

	tlsCertFileFlagName  = "tls-cert-file"
	tlsCertFileFlagUsage = "tls certificate file." +
		" Alternatively, this can be set with the following environment variable: " + tlsCertFileEnvKey
	tlsCertFileEnvKey = "ACRP_TLS_CERT_FILE"

	tlsKeyFileFlagName  = "tls-key-file"
	tlsKeyFileFlagUsage = "tls key file." +
		" Alternatively, this can be set with the following environment variable: " + tlsKeyFileEnvKey
	tlsKeyFileEnvKey = "ACRP_TLS_KEY_FILE"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ACRP_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ACRP_TLS_CACERTS"

	demoModeFlagName  = "demo-mode"
	demoModeFlagUsage = "Demo mode." +
		" Mandatory - Possible values [rev] [emp]."
	demoModeEnvKey = "ACRP_DEMO_MODE"
)

// nolint:gochecknoglobals
var supportedModes = map[string]string{"rev": "rev_agency", "emp": "emp_dept"}

var logger = log.New("acrp-rest")

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
	srv               server
	hostURL           string
	tlsCertFile       string
	tlsKeyFile        string
	tlsSystemCertPool bool
	tlsCACerts        []string
	logLevel          string
	dbParams          *common.DBParameters
	mode              string
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

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start AC RP",
		Long:  "Start Anonymous Comparator RP",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			dbParams, err := common.DBParams(cmd)
			if err != nil {
				return err
			}

			tlsConfg, err := getTLS(cmd)
			if err != nil {
				return err
			}

			loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, common.LogLevelFlagName, common.LogLevelEnvKey, true)
			if err != nil {
				return err
			}

			demoModeFlag, err := cmdutils.GetUserSetVarFromString(cmd, demoModeFlagName, demoModeEnvKey, false)
			if err != nil {
				return err
			}

			demoMode, ok := supportedModes[demoModeFlag]
			if !ok {
				return fmt.Errorf("invalid demo mode : %s", demoModeFlag)
			}

			parameters := &rpParameters{
				srv:               srv,
				hostURL:           strings.TrimSpace(hostURL),
				tlsCertFile:       tlsConfg.certFile,
				tlsKeyFile:        tlsConfg.keyFile,
				tlsSystemCertPool: tlsConfg.systemCertPool,
				tlsCACerts:        tlsConfg.caCerts,
				logLevel:          loggingLevel,
				dbParams:          dbParams,
				mode:              demoMode,
			}

			return startRP(parameters)
		},
	}
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
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(demoModeFlagName, "", "", demoModeFlagUsage)
	startCmd.Flags().StringP(common.LogLevelFlagName, common.LogLevelFlagShorthand, "", common.LogLevelPrefixFlagUsage)
}

func startRP(parameters *rpParameters) error {
	if parameters.logLevel != "" {
		common.SetDefaultLogLevel(logger, parameters.logLevel)
	}

	basePath := "static/" + parameters.mode
	router := pathPrefix(basePath)

	storeProvider, err := common.InitEdgeStore(parameters.dbParams, logger)
	if err != nil {
		return err
	}

	cfg := &operation.Config{
		StoreProvider: storeProvider,
		DashboardHTML: basePath + "/dashboard.html",
	}

	acrpService, err := acrp.New(cfg)
	if err != nil {
		return err
	}

	handlers := acrpService.GetOperations()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, parameters.tlsCertFile, parameters.tlsKeyFile, router)
}

func pathPrefix(path string) *mux.Router {
	router := mux.NewRouter()

	fs := http.FileServer(http.Dir(path))
	router.Handle("/", fs)
	router.PathPrefix("/img/").Handler(fs)
	router.PathPrefix("/showlogin").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path+"/login.html")
	})
	router.PathPrefix("/showregister").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path+"/register.html")
	})

	return router
}
