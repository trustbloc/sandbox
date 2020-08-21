/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
)

const (
	httpContentTypeJSON = "application/json"

	// api paths
	verifyVPPath         = "/verifyPresentation"
	oauth2GetRequestPath = "/oauth2/request"
	oauth2CallbackPath   = "/oauth2/callback"

	// api path params
	scopeQueryParam = "scope"

	// edge-service verifier endpoints
	verifyPresentationURLFormat = "/%s" + "/verifier/presentations"

	// TODO https://github.com/trustbloc/edge-sandbox/issues/352 Configure verifier profiles in Verifier page
	verifierProfileID = "verifier1"

	vcsVerifierRequestTokenName = "vcs_verifier" //nolint: gosec

	transientStoreName = "rp-rest-transient"
)

var logger = log.New("edge-sandbox-rp-restapi")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

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

// Operation defines handlers
type Operation struct {
	handlers         []Handler
	vpHTML           string
	vcsURL           string
	client           httpClient
	requestTokens    map[string]string
	transientStore   storage.Store
	oidcProvider     oidcProvider
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
	oauth2ConfigFunc func(...string) oauth2Config
	tlsConfig        *tls.Config
}

// Config defines configuration for rp operations
type Config struct {
	VPHTML                 string
	VCSURL                 string
	TLSConfig              *tls.Config
	RequestTokens          map[string]string
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCCallbackURL        string
	TransientStoreProvider storage.Provider
}

// vc struct used to return vc data to html
type vc struct {
	Data string `json:"data"`
	Msg  string `json:"msg"`
}

type createOIDCRequestResponse struct {
	Request string `json:"request"`
}

// New returns rp operation instance
func New(config *Config) (*Operation, error) {
	svc := &Operation{
		vpHTML:           config.VPHTML,
		vcsURL:           config.VCSURL,
		client:           &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:    config.RequestTokens,
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

	svc.transientStore, err = createStore(config.TransientStoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create store : %w", err)
	}

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

	svc.registerHandler()

	return svc, nil
}

// verifyVP
func (c *Operation) verifyVP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse form: %s", err.Error()))

		return
	}

	inputData := "vpDataInput"
	// TODO https://github.com/trustbloc/edge-sandbox/issues/194 RP Verifier - Support to configure
	//  checks for Credential and Presentation verifications
	checks := []string{"proof"}

	domain := r.Form.Get("domain")
	challenge := r.Form.Get("challenge")

	req := edgesvcops.VerifyPresentationRequest{
		Presentation: []byte(r.Form.Get(inputData)),
		Opts: &edgesvcops.VerifyPresentationOptions{
			Checks:    checks,
			Challenge: challenge,
			Domain:    domain,
		},
	}

	verifyPresentationEndpoint := fmt.Sprintf(verifyPresentationURLFormat, verifierProfileID)

	c.verify(verifyPresentationEndpoint, req, inputData, c.vpHTML, w, r)
}

func (c *Operation) createOIDCRequest(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get(scopeQueryParam)
	if scope == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing scope")

		return
	}

	// TODO validate scope

	state := uuid.New().String()
	redirectURL := c.oauth2Config(strings.Split(scope, " ")...).AuthCodeURL(state, oauth2.AccessTypeOnline)

	logger.Debugf("redirectURL: %s", redirectURL)

	response, err := json.Marshal(&createOIDCRequestResponse{
		Request: redirectURL,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal response : %s", err))

		return
	}

	err = c.transientStore.Put(state, []byte(state))
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write state to transient store : %s", err))

		return
	}

	w.Header().Set("content-type", "application/json")

	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write response : %s", err)
	}
}

func (c *Operation) handleOIDCCallback(w http.ResponseWriter, r *http.Request) { //nolint:funlen
	state := r.URL.Query().Get("state")
	if state == "" {
		logger.Errorf("missing state")
		c.didcommDemoResult(w, "missing state")

		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Errorf("missing code")
		c.didcommDemoResult(w, "missing code")

		return
	}

	_, err := c.transientStore.Get(state)
	if errors.Is(err, storage.ErrValueNotFound) {
		logger.Errorf("invalid state parameter")
		c.didcommDemoResult(w, "invalid state parameter")

		return
	}

	if err != nil {
		logger.Errorf("failed to query transient store for state : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to query transient store for state : %s", err))

		return
	}

	oauthToken, err := c.oauth2Config().Exchange(
		context.WithValue(
			r.Context(),
			oauth2.HTTPClient,
			&http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig}},
		),
		code)
	if err != nil {
		logger.Errorf("failed to exchange oauth2 code for token : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to exchange oauth2 code for token : %s", err))

		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		logger.Errorf("missing id_token")
		c.didcommDemoResult(w, "missing id_token")

		return
	}

	oidcToken, err := c.oidcProvider.Verifier(&oidc.Config{
		ClientID: c.oidcClientID,
	}).Verify(r.Context(), rawIDToken)
	if err != nil {
		logger.Errorf("failed to verify id_token : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to verify id_token : %s", err))

		return
	}

	userData := make(map[string]interface{})

	err = oidcToken.Claims(&userData)
	if err != nil {
		logger.Errorf("failed to extract user data from id_token : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to extract user data from id_token : %s", err))

		return
	}

	bits, err := json.Marshal(userData)
	if err != nil {
		logger.Errorf("failed to marshal user data : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to marshal user data : %s", err))

		return
	}

	c.didcommDemoResult(w, string(bits))
}

func (c *Operation) didcommDemoResult(w http.ResponseWriter, data string) {
	t, err := template.ParseFiles(c.vpHTML)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, vc{Data: data}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

// verify function verifies the input data and parse the response to provided template
func (c *Operation) verify(endpoint string, verifyReq interface{}, inputData, htmlTemplate string, //nolint:funlen
	w http.ResponseWriter, r *http.Request) {
	reqBytes, err := json.Marshal(verifyReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal request : %s", err.Error()))

		return
	}

	t, err := template.ParseFiles(htmlTemplate)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	resp, httpErr := c.sendHTTPRequest(http.MethodPost, c.vcsURL+endpoint, reqBytes, httpContentTypeJSON,
		c.requestTokens[vcsVerifierRequestTokenName])
	if httpErr != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify: %s", httpErr.Error()))

		if err := t.Execute(w, vc{Msg: "Oops verification is failed, Try again"}); err != nil {
			logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
		}

		return
	}

	if resp.StatusCode != http.StatusOK {
		failedMsg := ""

		respBytes, respErr := ioutil.ReadAll(resp.Body)
		if respErr != nil {
			failedMsg = fmt.Sprintf("failed to read response body: %s", respErr)
		} else {
			failedMsg = string(respBytes)
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("closing response body failed: %v", e)
			}
		}()

		c.writeErrorResponse(w, resp.StatusCode, fmt.Sprintf("failed to verify: %s", failedMsg))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, vc{Msg: "Successfully verified", Data: r.Form.Get(inputData)}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) sendHTTPRequest(method, url string, body []byte, contentType,
	token string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+c.requestTokens[vcsVerifierRequestTokenName])
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	return c.client.Do(req)
}

// writeResponse writes interface value to response
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	logger.Errorf(msg)

	rw.WriteHeader(status)

	write := rw.Write
	if _, err := write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(verifyVPPath, http.MethodPost, c.verifyVP),
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func (c *Operation) oauth2Config(scopes ...string) oauth2Config {
	return c.oauth2ConfigFunc(scopes...)
}

func createStore(p storage.Provider) (storage.Store, error) {
	err := p.CreateStore(transientStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create store [%s] : %w", transientStoreName, err)
	}

	return p.OpenStore(transientStoreName)
}
