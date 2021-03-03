/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
)

const (
	// LogLevelFlagName is the flag name used for setting the default log level.
	LogLevelFlagName = "log-level"
	// LogLevelEnvKey is the env var name used for setting the default log level.
	LogLevelEnvKey = "LOG_LEVEL"
	// LogLevelFlagShorthand is the shorthand flag name used for setting the default log level.
	LogLevelFlagShorthand = "l"
	// LogLevelPrefixFlagUsage is the usage text for the log level flag.
	LogLevelPrefixFlagUsage = "Logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + LogLevelEnvKey
)

const (
	// DatabaseURLFlagName is the database url.
	DatabaseURLFlagName = "database-url"
	// DatabaseURLFlagUsage describes the usage.
	DatabaseURLFlagUsage = "Database URL with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, mysql, couchdb]." +
		" Alternatively, this can be set with the following environment variable: " + DatabaseURLEnvKey
	// DatabaseURLEnvKey is the databaes url.
	DatabaseURLEnvKey = "DATABASE_URL"

	// DatabaseTimeoutFlagName is the database timeout.
	DatabaseTimeoutFlagName = "database-timeout"
	// DatabaseTimeoutFlagUsage describes the usage.
	DatabaseTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: " + string(rune(DatabaseTimeoutDefault)) + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + DatabaseTimeoutEnvKey
	// DatabaseTimeoutEnvKey is the database timeout.
	DatabaseTimeoutEnvKey = "DATABASE_TIMEOUT"

	// DatabasePrefixFlagName is the storage prefix.
	DatabasePrefixFlagName = "database-prefix"
	// DatabasePrefixEnvKey is the storage prefix.
	DatabasePrefixEnvKey = "DATABASE_PREFIX"
	// DatabasePrefixFlagUsage describes the usage.
	DatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		"Alternatively, this can be set with the following environment variable: " + DatabasePrefixEnvKey

	// DatabaseTimeoutDefault is the default storage timeout.
	DatabaseTimeoutDefault = 30
)

// DBParameters holds database configuration.
type DBParameters struct {
	URL     string
	Prefix  string
	Timeout uint64
}

// nolint:gochecknoglobals
var supportedEdgeStorageProviders = map[string]func(string, string) (storage.Provider, error){
	"mysql": func(dbURL, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dbURL, mysql.WithDBPrefix(prefix))
	},
	"mem": func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	"couchdb": func(dbURL, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dbURL, couchdb.WithDBPrefix(prefix))
	},
}

// SetDefaultLogLevel sets the default log level.
func SetDefaultLogLevel(logger log.Logger, userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warnf(`%s is not a valid logging level. It must be one of the following: `+
			log.ParseString(log.CRITICAL)+", "+
			log.ParseString(log.ERROR)+", "+
			log.ParseString(log.WARNING)+", "+
			log.ParseString(log.INFO)+", "+
			log.ParseString(log.DEBUG)+". Defaulting to info.", userLogLevel)

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Infof(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}

// Flags registers common command flags.
func Flags(cmd *cobra.Command) {
	cmd.Flags().StringP(DatabaseURLFlagName, "", "", DatabaseURLFlagUsage)
	cmd.Flags().StringP(DatabasePrefixFlagName, "", "", DatabasePrefixFlagUsage)
	cmd.Flags().StringP(DatabaseTimeoutFlagName, "", "", DatabaseTimeoutFlagUsage)
}

// DBParams fetches the DB parameters configured for this command.
func DBParams(cmd *cobra.Command) (*DBParameters, error) {
	var err error

	params := &DBParameters{}

	params.URL, err = cmdutils.GetUserSetVarFromString(cmd, DatabaseURLFlagName, DatabaseURLEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dbURL: %w", err)
	}

	params.Prefix, err = cmdutils.GetUserSetVarFromString(cmd, DatabasePrefixFlagName, DatabasePrefixEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to configure dbPrefix: %w", err)
	}

	timeout, err := cmdutils.GetUserSetVarFromString(cmd, DatabaseTimeoutFlagName, DatabaseTimeoutEnvKey, true)
	if err != nil && !strings.Contains(err.Error(), "value is empty") {
		return nil, fmt.Errorf("failed to configure dbTimeout: %w", err)
	}

	if timeout == "" {
		timeout = strconv.Itoa(DatabaseTimeoutDefault)
	}

	params.Timeout, err = strconv.ParseUint(timeout, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dbTimeout %s: %w", timeout, err)
	}

	return params, nil
}

// InitEdgeStore provider.
func InitEdgeStore(params *DBParameters, logger log.Logger) (storage.Provider, error) {
	const (
		sleep    = 1 * time.Second
		urlParts = 2
	)

	numRetries := uint64(DatabaseTimeoutDefault)

	if params.Timeout > 0 {
		numRetries = params.Timeout
	}

	parsed := strings.SplitN(params.URL, ":", urlParts)

	if len(parsed) != urlParts {
		return nil, fmt.Errorf("invalid dbURL %s", params.URL)
	}

	driver := parsed[0]
	dsn := strings.TrimPrefix(parsed[1], "//")

	providerFunc, supported := supportedEdgeStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store storage.Provider

	err := backoff.RetryNotify(
		func() error {
			var openErr error
			store, openErr = providerFunc(dsn, params.Prefix)
			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to storage at %s : %w", dsn, err)
	}

	return store, nil
}
