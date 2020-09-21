/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-core/pkg/log"
)

const (
	oauth2CallbackPath = "/oauth2/callback"
)

var logger = log.New("oidc")

type oidcProvider interface {
	Endpoint() oauth2.Endpoint
	Verifier(*oidc.Config) verifier
}

type oidcProviderImpl struct {
	op *oidc.Provider
}

func (o *oidcProviderImpl) Endpoint() oauth2.Endpoint {
	return o.op.Endpoint()
}

func (o *oidcProviderImpl) Verifier(config *oidc.Config) verifier {
	return &verifierImpl{v: o.op.Verifier(config)}
}

type verifier interface {
	Verify(context.Context, string) (idToken, error)
}

type verifierImpl struct {
	v *oidc.IDTokenVerifier
}

func (v *verifierImpl) Verify(ctx context.Context, token string) (idToken, error) {
	return v.v.Verify(ctx, token)
}

type idToken interface {
	Claims(interface{}) error
}

type oauth2Config interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string, ...oauth2.AuthCodeOption) (oauth2Token, error)
}

type oauth2ConfigImpl struct {
	oc *oauth2.Config
}

func (o *oauth2ConfigImpl) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return o.oc.AuthCodeURL(state, options...)
}

func (o *oauth2ConfigImpl) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return o.oc.Exchange(ctx, code, options...)
}

type oauth2Token interface {
	Extra(string) interface{}
}

// Client for oidc
type Client struct {
	oidcProvider     oidcProvider
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
	oauth2ConfigFunc func(...string) oauth2Config
	tlsConfig        *tls.Config
}

// Config defines configuration for oidc client
type Config struct {
	TLSConfig        *tls.Config
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCCallbackURL  string
}

// New returns client instance
func New(config *Config) (*Client, error) {
	svc := &Client{
		oidcClientID:     config.OIDCClientID,
		oidcClientSecret: config.OIDCClientSecret,
		oidcCallbackURL:  config.OIDCCallbackURL,
		tlsConfig:        config.TLSConfig,
	}

	idp, err := oidc.NewProvider(
		oidc.ClientContext(
			context.Background(),
			&http.Client{
				Transport: &http.Transport{TLSClientConfig: config.TLSConfig},
			},
		),
		config.OIDCProviderURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider with url [%s] : %w", config.OIDCProviderURL, err)
	}

	svc.oidcProvider = &oidcProviderImpl{op: idp}

	svc.oauth2ConfigFunc = func(scopes ...string) oauth2Config {
		config := &oauth2.Config{
			ClientID:     svc.oidcClientID,
			ClientSecret: svc.oidcClientSecret,
			Endpoint:     svc.oidcProvider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s%s", svc.oidcCallbackURL, oauth2CallbackPath),
			Scopes:       []string{oidc.ScopeOpenID},
		}

		if len(scopes) > 0 {
			config.Scopes = append(config.Scopes, scopes...)
		}

		return &oauth2ConfigImpl{oc: config}
	}

	return svc, nil
}

// CreateOIDCRequest create oidc request
func (c *Client) CreateOIDCRequest(state, scope string) (string, error) {
	redirectURL := c.oauth2Config(strings.Split(scope, " ")...).AuthCodeURL(state, oauth2.AccessTypeOnline)

	logger.Debugf("redirectURL: %s", redirectURL)

	return redirectURL, nil
}

// HandleOIDCCallback handle oidc callback
func (c *Client) HandleOIDCCallback(reqContext context.Context, code string) ([]byte, error) {
	oauthToken, err := c.oauth2Config().Exchange(
		context.WithValue(
			reqContext,
			oauth2.HTTPClient,
			&http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig}},
		),
		code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange oauth2 code for token : %s", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token : %s", err)
	}

	oidcToken, err := c.oidcProvider.Verifier(&oidc.Config{
		ClientID: c.oidcClientID,
	}).Verify(reqContext, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token : %s", err)
	}

	userData := make(map[string]interface{})

	err = oidcToken.Claims(&userData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user data from id_token : %s", err)
	}

	bits, err := json.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user data : %s", err)
	}

	return bits, nil
}

func (c *Client) oauth2Config(scopes ...string) oauth2Config {
	return c.oauth2ConfigFunc(scopes...)
}
