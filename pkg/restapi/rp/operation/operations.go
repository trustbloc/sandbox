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
	TransientStoreProvider storage.Provider
}

// vc struct used to return vc data to html
type vc struct {
	Data string `json:"data"`
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
	}

	var err error

	svc.oidcProvider, err = oidc.NewProvider(
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

	svc.transientStore, err = createStore(config.TransientStoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create store : %w", err)
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

	oauth2Config := &oauth2.Config{
		ClientID:     c.oidcClientID,
		ClientSecret: c.oidcClientSecret,
		Endpoint:     c.oidcProvider.Endpoint(),
		RedirectURL:  oauth2CallbackPath, // TODO set full callback path properly
		Scopes:       []string{oidc.ScopeOpenID, scope},
	}

	state := uuid.New().String()
	redirectURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)

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

// verify function verifies the input data and parse the response to provided template
func (c *Operation) verify(endpoint string, verifyReq interface{}, inputData, htmlTemplate string,
	w http.ResponseWriter, r *http.Request) {
	reqBytes, err := json.Marshal(verifyReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal request : %s", err.Error()))

		return
	}

	resp, httpErr := c.sendHTTPRequest(http.MethodPost, c.vcsURL+endpoint, reqBytes, httpContentTypeJSON,
		c.requestTokens[vcsVerifierRequestTokenName])
	if httpErr != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify: %s", httpErr.Error()))

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

	t, err := template.ParseFiles(htmlTemplate)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Data: r.Form.Get(inputData)}); err != nil {
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

	if _, err := rw.Write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(verifyVPPath, http.MethodPost, c.verifyVP),
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func createStore(p storage.Provider) (storage.Store, error) {
	err := p.CreateStore(transientStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create store [%s] : %w", transientStoreName, err)
	}

	return p.OpenStore(transientStoreName)
}
