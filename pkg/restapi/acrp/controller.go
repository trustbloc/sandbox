/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acrp

import (
	"github.com/trustbloc/edge-sandbox/pkg/restapi/acrp/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	var allHandlers []operation.Handler

	acrpService := operation.New(config)

	allHandlers = append(allHandlers, acrpService.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
