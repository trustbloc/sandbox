/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
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
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/component', 'mem://test'," +
		"'mongodb://mongodb.example.com:27017'. Supported drivers are [mem, mysql, couchdb, mongodb]." +
		" Alternatively, this can be set with the following environment variable: " + DatabaseURLEnvKey
	// DatabaseURLEnvKey is the database url.
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

	databaseTypeMemOption     = "mem"
	databaseTypeMYSQLDBOption = "mysql"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMongoDBOption = "mongodb"
)

// DBParameters holds database configuration.
type DBParameters struct {
	URL     string
	Prefix  string
	Timeout uint64
}

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeMYSQLDBOption: func(dbURL, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dbURL, mysql.WithDBPrefix(prefix))
	},
	databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	databaseTypeCouchDBOption: func(dbURL, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dbURL, couchdb.WithDBPrefix(prefix))
	},
	databaseTypeMongoDBOption: func(dbURL, prefix string) (storage.Provider, error) {
		return mongodb.NewProvider(dbURL, mongodb.WithDBPrefix(prefix))
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

// InitStore provider.
func InitStore(params *DBParameters, logger log.Logger) (storage.Provider, error) {
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

	var dsn string
	if driver == databaseTypeMongoDBOption {
		// The MongoDB storage provider needs the full connection string (including the driver as part of it).
		dsn = params.URL
	} else {
		dsn = strings.TrimPrefix(parsed[1], "//")
	}

	providerFunc, supported := supportedStorageProviders[driver]
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

// LDStoreProvider provides stores for JSON-LD contexts and remote providers.
type LDStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

// JSONLDContextStore returns a JSON-LD context store.
func (p *LDStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

// JSONLDRemoteProviderStore returns a JSON-LD remote provider store.
func (p *LDStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// CreateLDStoreProvider creates a new LDStoreProvider.
func CreateLDStoreProvider(storageProvider storage.Provider) (*LDStoreProvider, error) {
	contextStore, err := ldstore.NewContextStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &LDStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

type ldStoreProvider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CreateJSONLDDocumentLoader creates a new JSON-LD document loader.
func CreateJSONLDDocumentLoader(ldStore ldStoreProvider, client httpClient,
	providerURLs []string) (jsonld.DocumentLoader, error) {
	var loaderOpts []ld.DocumentLoaderOpts

	for _, u := range providerURLs {
		loaderOpts = append(loaderOpts,
			ld.WithRemoteProvider(
				remote.NewProvider(u, remote.WithHTTPClient(client)),
			),
		)
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}
