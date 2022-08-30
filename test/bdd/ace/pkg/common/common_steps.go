/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/cucumber/godog"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/tidwall/gjson"
	"github.com/trustbloc/ace/pkg/httpsig"

	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/internal/httputil"
	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/internal/vdrutil"
)

const (
	healthCheckURL = "https://%s:%d/healthcheck"
)

// Steps defines context for common scenario steps.
type Steps struct {
	HTTPClient         *http.Client
	VDR                vdrapi.Registry
	responseStatus     string
	responseStatusCode int
	responseBody       []byte
}

// NewSteps returns new Steps context.
func NewSteps(tlsConfig *tls.Config) (*Steps, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	if os.Getenv("HTTP_CLIENT_TRACE_ON") == "true" {
		httpClient = httputil.WrapWithDumpTransport(httpClient)
	}

	vdr, err := vdrutil.CreateVDR(httpClient)
	if err != nil {
		return nil, err
	}

	return &Steps{
		HTTPClient: httpClient,
		VDR:        vdr,
	}, nil
}

// RegisterSteps registers common scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^an HTTP GET is sent to "([^"]*)"$`, s.httpGet)
	sc.Step(`^an HTTP PUT with bearer token "([^"]*)" is sent to "([^"]*)"$`, s.httpPutWithToken)
	sc.Step(`^an HTTP POST is sent to "([^"]*)"$`, s.httpPost)
	sc.Step(`^an HTTP GET with "([^"]*)" headers signed by "([^"]*)" is sent to "([^"]*)"$`, s.httpGetSigned)
	sc.Step(`^an HTTP POST with "([^"]*)" headers signed by "([^"]*)" is sent to "([^"]*)"$`, s.httpPostSigned)
	sc.Step(`^an HTTP POST with "([^"]*)" headers signed by "([^"]*)" is sent to "([^"]*)" with body$`, s.httpPostSignedWithBody) //nolint:lll
	sc.Step(`^response status is "([^"]*)"$`, s.checkResponseStatus)
	sc.Step(`^response contains "([^"]*)" with value "([^"]*)"$`, s.checkResponseValue)
	sc.Step(`^response contains non-empty "([^"]*)"$`, s.checkNonEmptyResponseValue)
}

type healthCheckResponse struct {
	Status string `json:"status"`
}

// HealthCheck checks if service on host:port is up and running.
func (s *Steps) HealthCheck(ctx context.Context, host string, port int) error {
	url := fmt.Sprintf(healthCheckURL, host, port)

	var resp healthCheckResponse

	r, err := httputil.DoRequest(ctx, url, httputil.WithHTTPClient(s.HTTPClient),
		httputil.WithParsedResponse(&resp))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = r.Status
	s.responseBody = r.Body

	if r.StatusCode == http.StatusOK && resp.Status == "success" {
		return nil
	}

	return errors.New("health check failure")
}

type contextKey string

// SignerOpts represents signer options.
type SignerOpts struct {
	PublicKeyID string
	PrivateKey  ed25519.PrivateKey
}

// ContextWithSignerOpts returns a new context with options for a request signer.
func ContextWithSignerOpts(ctx context.Context, name string, opts *SignerOpts) context.Context {
	return context.WithValue(ctx, contextKey(name), opts)
}

func (s *Steps) httpGet(ctx context.Context, url string) error {
	return s.httpDo(ctx, http.MethodGet, url, nil)
}

func (s *Steps) httpPutWithToken(ctx context.Context, token, url string, docStr *godog.DocString) error {
	return s.httpDo(ctx, http.MethodPut, url, docStr, httputil.WithAuthToken(token))
}

func (s *Steps) httpPost(ctx context.Context, url string, docStr *godog.DocString) error {
	return s.httpDo(ctx, http.MethodPost, url, docStr)
}

func (s *Steps) httpGetSigned(ctx context.Context, headers, signer, url string) error {
	sig, err := getSigner(ctx, headers, signer)
	if err != nil {
		return fmt.Errorf("get signer for http get: %w", err)
	}

	return s.httpDo(ctx, http.MethodGet, url, nil, httputil.WithSigner(sig))
}

func (s *Steps) httpPostSigned(ctx context.Context, headers, signer, url string) error {
	sig, err := getSigner(ctx, headers, signer)
	if err != nil {
		return fmt.Errorf("get signer for http post: %w", err)
	}

	return s.httpDo(ctx, http.MethodPost, url, nil, httputil.WithSigner(sig))
}

func (s *Steps) httpPostSignedWithBody(ctx context.Context, headers, signer, url string,
	bodyTemplate *godog.DocString) error {
	sig, err := getSigner(ctx, headers, signer)
	if err != nil {
		return fmt.Errorf("get signer for http post: %w", err)
	}

	return s.httpDo(ctx, http.MethodPost, url, bodyTemplate, httputil.WithSigner(sig))
}

func getSigner(ctx context.Context, headers, signer string) (*RequestSigner, error) {
	opts, ok := ctx.Value(contextKey(signer)).(*SignerOpts)
	if !ok {
		return nil, fmt.Errorf("missing %q signer options in context", signer)
	}

	return &RequestSigner{
		Headers:     strings.Split(headers, ","),
		PublicKeyID: opts.PublicKeyID,
		PrivateKey:  opts.PrivateKey,
	}, nil
}

func (s *Steps) httpDo(ctx context.Context, method, url string, bodyTemplate *godog.DocString,
	opts ...httputil.Opt) error {
	opts = append(opts, httputil.WithHTTPClient(s.HTTPClient), httputil.WithMethod(method))

	if strings.Contains(url, "{ticket_id}") {
		url = strings.ReplaceAll(url, "{ticket_id}", ctx.Value("ticket_id").(string))
	}

	if strings.Contains(url, "GATEKEEPER_HOST") {
		url = strings.ReplaceAll(url, "GATEKEEPER_HOST", os.Getenv("GATEKEEPER_HOST"))
	}

	if bodyTemplate != nil {
		t, err := template.New("body").Parse(bodyTemplate.Content)
		if err != nil {
			return fmt.Errorf("parse body template: %w", err)
		}

		var buf bytes.Buffer

		err = t.Execute(&buf, ctx)
		if err != nil {
			return fmt.Errorf("execute body template: %w", err)
		}

		opts = append(opts, httputil.WithBody(buf.Bytes()))
	}

	r, err := httputil.DoRequest(ctx, url, opts...)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	s.responseStatus = r.Status
	s.responseStatusCode = r.StatusCode
	s.responseBody = r.Body

	return nil
}

func (s *Steps) checkResponseStatus(status string) error {
	if s.responseStatus != status {
		return fmt.Errorf("expected %q, got %q", status, s.responseStatus)
	}

	return nil
}

func (s *Steps) checkResponseValue(path, value string) error {
	res := gjson.Get(string(s.responseBody), path)

	if res.Str != value {
		return fmt.Errorf("got %q", res.Str)
	}

	return nil
}

func (s *Steps) checkNonEmptyResponseValue(ctx context.Context, path string) (context.Context, error) {
	res := gjson.Get(string(s.responseBody), path)

	if res.Str == "" {
		return ctx, fmt.Errorf("got empty value")
	}

	return context.WithValue(ctx, path, res.Str), nil //nolint:golint,revive,staticcheck
}

// RequestSigner is a signer in HTTP Signatures auth method.
type RequestSigner struct {
	Headers     []string
	PublicKeyID string
	PrivateKey  ed25519.PrivateKey
}

// Sign signs an HTTP request.
func (s *RequestSigner) Sign(req *http.Request) error {
	signer := httpsig.NewSigner(httpsig.SignerConfig{Headers: s.Headers}, s.PrivateKey)

	if err := signer.SignRequest(s.PublicKeyID, req); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	return nil
}
