/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sandbox/pkg/token"
)

const tokenFormKey = "token"

var logger = log.New("sandbox-token-resolver")

// Option configures the resolver
type Option func(opts *Resolver)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Resolver) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// Resolver implements token resolution
type Resolver struct {
	tokenIntrospectionURL string
	httpClient            *http.Client
}

// New creates new token resolver
func New(tokenIntrospectionURL string, opts ...Option) *Resolver {
	resolver := &Resolver{tokenIntrospectionURL: tokenIntrospectionURL, httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(resolver)
	}

	return resolver
}

// Resolve returns token information based on token
func (r *Resolver) Resolve(tk string) (*token.Introspection, error) {
	resp, err := r.httpClient.PostForm(r.tokenIntrospectionURL,
		url.Values{tokenFormKey: {tk}})
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	return getTokenInfo(resp)
}

func getTokenInfo(resp *http.Response) (*token.Introspection, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("http status code is not ok")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	info := &token.Introspection{}

	err = json.Unmarshal(body, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}
