/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

type protectRequest struct {
	Policy string `json:"policy"`
	Target string `json:"target"`
}

type protectResponse struct {
	DID string `json:"did"`
}

type releaseRequest struct {
	DID string `json:"did"`
}

type releaseResponse struct {
	TicketID string `json:"ticket_id"`
}
