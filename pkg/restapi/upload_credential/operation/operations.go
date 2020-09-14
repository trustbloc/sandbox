/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("upload-cred-restapi")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers
type Operation struct {
	handlers      []Handler
	requestTokens map[string]string
	tlsConfig     *tls.Config
}

// Config defines configuration for upload cred operations
type Config struct {
	TLSConfig     *tls.Config
	RequestTokens map[string]string
}

// New returns upload cred operation instance
func New(config *Config) (*Operation, error) {
	logger.Debugf("create new instance")

	svc := &Operation{
		requestTokens: config.RequestTokens,
		tlsConfig:     config.TLSConfig,
	}

	svc.registerHandler()

	return svc, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}
