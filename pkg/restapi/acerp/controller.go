/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acerp

import (
	"fmt"

	"github.com/trustbloc/sandbox/pkg/restapi/acerp/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	var allHandlers []operation.Handler

	aceRpService, err := operation.New(config)
	if err != nil {
		return nil, fmt.Errorf("create ace-rp operation : %w", err)
	}

	allHandlers = append(allHandlers, aceRpService.GetRESTHandlers()...)

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
