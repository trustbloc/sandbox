/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
	authorization   = "Authorization"
)

var logger = log.New("ace-bdd")

// Response is an HTTP response.
type Response struct {
	Status       string
	StatusCode   int
	Body         []byte
	ErrorMessage string
}

// DoRequest makes an HTTP request.
func DoRequest(ctx context.Context, url string, opts ...Opt) (*Response, error) {
	op := &options{
		httpClient: http.DefaultClient,
		method:     http.MethodGet,
	}

	for _, fn := range opts {
		fn(op)
	}

	req, err := http.NewRequestWithContext(ctx, op.method, url, op.body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Add(contentType, applicationJSON)

	if op.authToken != "" {
		req.Header.Add(authorization, "Bearer "+op.authToken)
	}

	if op.signer != nil {
		if err = op.signer.Sign(req); err != nil {
			return nil, fmt.Errorf("sign http request: %w", err)
		}
	}

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	return readResponse(op, resp)
}

// DoRequest makes an HTTP request.
func readResponse(op *options, resp *http.Response) (*Response, error) {
	r := &Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if len(body) > 0 {
		r.Body = body

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse

			if err = json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
				return nil, errors.New(errResp.Message)
			}

			return nil, errors.New(resp.Status)
		}
	}

	if op.parsedResponse != nil {
		if err = json.Unmarshal(body, op.parsedResponse); err != nil {
			return nil, fmt.Errorf("unmarshal response body: %w", err)
		}
	}

	return r, nil
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

type requestSigner interface {
	Sign(req *http.Request) error
}

type options struct {
	httpClient     *http.Client
	method         string
	body           io.Reader
	authToken      string
	signer         requestSigner
	parsedResponse interface{}
}

// Opt configures HTTP request options.
type Opt func(*options)

// WithHTTPClient specifies the custom HTTP client.
func WithHTTPClient(c *http.Client) Opt {
	return func(o *options) {
		o.httpClient = c
	}
}

// WithMethod specifies an HTTP method. Default is GET.
func WithMethod(val string) Opt {
	return func(o *options) {
		o.method = val
	}
}

// WithBody specifies HTTP request body.
func WithBody(val []byte) Opt {
	return func(o *options) {
		o.body = bytes.NewBuffer(val)
	}
}

// WithAuthToken specifies an authorization token.
func WithAuthToken(token string) Opt {
	return func(o *options) {
		o.authToken = token
	}
}

// WithSigner specifies a request signer for HTTP Signatures.
func WithSigner(signer requestSigner) Opt {
	return func(o *options) {
		o.signer = signer
	}
}

// WithParsedResponse specifies type to unmarshal response body.
func WithParsedResponse(r interface{}) Opt {
	return func(o *options) {
		o.parsedResponse = r
	}
}

// WrapWithDumpTransport wraps existing http.Client's transport with transport that dumps requests and responses.
func WrapWithDumpTransport(client *http.Client) *http.Client {
	client.Transport = &DumpTransport{r: client.Transport}

	return client
}

// DumpTransport is http.RoundTripper that dumps requests and responses.
type DumpTransport struct {
	r http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (d *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	fmt.Printf("\n****REQUEST****\n%s\n\n", string(reqDump))

	resp, err := d.r.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %w", err)
	}

	fmt.Printf("****RESPONSE****\n%s****************\n", string(respDump))

	return resp, err
}
