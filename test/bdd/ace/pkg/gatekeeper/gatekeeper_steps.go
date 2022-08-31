/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gatekeeper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/template"

	"github.com/cucumber/godog"

	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/common"
	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/internal/httputil"
	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/internal/vdrutil"
)

const (
	authToken = "gk_token"
)

// DIDOwner defines parameters of a DID owner.
type DIDOwner struct {
	DID         string
	PublicKeyID string
	PrivateKey  ed25519.PrivateKey
}

// Steps defines context for Gatekeeper scenario steps.
type Steps struct {
	cs        *common.Steps
	didOwners map[string]*DIDOwner
	policyID  string
	targetDID string
	ticketID  string
	host      string
}

// NewSteps returns new Steps context.
func NewSteps(commonSteps *common.Steps) *Steps {
	return &Steps{
		cs:        commonSteps,
		didOwners: make(map[string]*DIDOwner),
		host:      os.Getenv("GATEKEEPER_HOST"),
	}
}

// RegisterSteps registers Gatekeeper scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Gatekeeper is running on "([^"]*)" port "([^"]*)"$`, s.cs.HealthCheck)
	sc.Step(`^did owner with name "([^"]*)"$`, s.createDIDOwner)
	sc.Step(`^policy configuration with ID "([^"]*)"$`, s.createPolicy)
	sc.Step(`^social media handle "([^"]*)" converted into DID by "([^"]*)"$`, s.convertIntoDID)
	sc.Step(`^release transaction created on DID by "([^"]*)"$`, s.createTicket)
}

func (s *Steps) createDIDOwner(ctx context.Context, name string) (context.Context, error) {
	doc, pk, err := vdrutil.CreateDIDDoc(s.cs.VDR)
	if err != nil {
		return context.Background(), fmt.Errorf("create did doc: %w", err)
	}

	_, err = vdrutil.ResolveDID(s.cs.VDR, doc.ID, 10)
	if err != nil {
		return context.Background(), fmt.Errorf("resolve did: %w", err)
	}

	didOwner := &DIDOwner{
		DID:         doc.ID,
		PublicKeyID: doc.Authentication[0].VerificationMethod.ID,
		PrivateKey:  pk,
	}

	s.didOwners[name] = didOwner

	return common.ContextWithSignerOpts(ctx, name, &common.SignerOpts{
		PublicKeyID: didOwner.PublicKeyID,
		PrivateKey:  didOwner.PrivateKey,
	}), nil
}

func (s *Steps) createPolicy(ctx context.Context, policyID string, policy *godog.DocString) error {
	t, err := template.New("policy").Parse(policy.Content)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, s)
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	_, err = httputil.DoRequest(ctx, fmt.Sprintf("https://%s/v1/policy/%s", s.host, policyID),
		httputil.WithHTTPClient(s.cs.HTTPClient), httputil.WithMethod(http.MethodPut), httputil.WithBody(buf.Bytes()),
		httputil.WithAuthToken(authToken))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.policyID = policyID

	return nil
}

func (s *Steps) convertIntoDID(ctx context.Context, handle, didOwner string) (context.Context, error) {
	req := &protectRequest{
		Policy: s.policyID,
		Target: handle,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return context.Background(), fmt.Errorf("marshal request: %w", err)
	}

	owner, ok := s.didOwners[didOwner]
	if !ok {
		return context.Background(), fmt.Errorf("missing did owner %q", didOwner)
	}

	var resp protectResponse

	_, err = httputil.DoRequest(ctx, fmt.Sprintf("https://%s/v1/protect", s.host),
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(reqBytes),
		httputil.WithHTTPClient(s.cs.HTTPClient),
		httputil.WithParsedResponse(&resp),
		httputil.WithSigner(&common.RequestSigner{
			Headers:     []string{"(request-target)", "date", "digest"},
			PublicKeyID: owner.PublicKeyID,
			PrivateKey:  owner.PrivateKey,
		}))
	if err != nil {
		return context.Background(), fmt.Errorf("do request: %w", err)
	}

	s.targetDID = resp.DID

	return context.WithValue(ctx, "targetDID", s.targetDID), nil //nolint:golint,revive,staticcheck
}

func (s *Steps) createTicket(ctx context.Context, didOwner string) (context.Context, error) {
	req := &releaseRequest{
		DID: s.targetDID,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return context.Background(), fmt.Errorf("marshal release request: %w", err)
	}

	owner, ok := s.didOwners[didOwner]
	if !ok {
		return context.Background(), fmt.Errorf("missing did owner %q", didOwner)
	}

	var resp releaseResponse

	_, err = httputil.DoRequest(ctx, fmt.Sprintf("https://%s/v1/release", s.host),
		httputil.WithHTTPClient(s.cs.HTTPClient),
		httputil.WithMethod(http.MethodPost),
		httputil.WithBody(reqBytes),
		httputil.WithParsedResponse(&resp),
		httputil.WithSigner(&common.RequestSigner{
			Headers:     []string{"(request-target)", "date", "digest"},
			PublicKeyID: owner.PublicKeyID,
			PrivateKey:  owner.PrivateKey,
		}))
	if err != nil {
		return context.Background(), fmt.Errorf("do request: %w", err)
	}

	s.ticketID = resp.TicketID

	return context.WithValue(ctx, "ticket_id", s.ticketID), nil //nolint:golint,revive,staticcheck
}

// GetDID is a helper function used in template to get DID by owner name.
func (s *Steps) GetDID(didOwner string) string {
	return s.didOwners[didOwner].DID
}
