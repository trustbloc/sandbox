/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const tokenFormKey = "token"

// Resolver implements token resolution
type Resolver struct {
	tokenIntrospectionURL string
}

// New creates new token resolver
func New(tokenIntrospectionURL string) *Resolver {
	return &Resolver{tokenIntrospectionURL: tokenIntrospectionURL}
}

// Resolve returns token information based on token
func (r *Resolver) Resolve(tk string) (*token.Introspection, error) {
	resp, err := http.PostForm(r.tokenIntrospectionURL,
		url.Values{tokenFormKey: {tk}})
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Warn("failed to close response body")
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
