/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers
type Operation struct {
	handlers     []Handler
	vcHTML       string
	vcServiceURL string
}

// Config defines configuration for rp operations
type Config struct {
	VCHTML       string
	VCServiceURL string
}

// New returns rp operation instance
func New(config *Config) *Operation {
	svc := &Operation{
		vcHTML: config.VCHTML, vcServiceURL: config.VCServiceURL}
	svc.registerHandler()

	return svc
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
