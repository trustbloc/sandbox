/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/vc/operation"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
)

const (
	httpContentTypeJSON = "application/json"

	// api paths
	verifyVCPath = "/verify"
	verifyVPPath = "/verifyPresentation"

	// edge-service verifier endpoints
	verifyCredentialEndpoint   = "/verifier/credentials"
	verifyPresentationEndpoint = "/verifier/presentations"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}

// Operation defines handlers
type Operation struct {
	handlers []Handler
	vcHTML   string
	vpHTML   string
	vcsURL   string
	client   httpClient
}

// Config defines configuration for rp operations
type Config struct {
	VCHTML    string
	VPHTML    string
	VCSURL    string
	TLSConfig *tls.Config
}

// vc struct used to return vc data to html
type vc struct {
	Data string `json:"data"`
}

// New returns rp operation instance
func New(config *Config) *Operation {
	svc := &Operation{
		vcHTML: config.VCHTML,
		vpHTML: config.VPHTML,
		vcsURL: config.VCSURL,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}}}
	svc.registerHandler()

	return svc
}

// verifyVC
func (c *Operation) verifyVC(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse form: %s", err.Error()))

		return
	}

	inputData := "vcDataInput"
	// TODO https://github.com/trustbloc/edge-sandbox/issues/194 RP Verifier - Support to configure
	//  checks for Credential and Presentation verifications
	checks := []string{"proof", "status"}

	req := edgesvcops.CredentialsVerificationRequest{
		Credential: []byte(r.Form.Get(inputData)),
		Opts: &edgesvcops.CredentialsVerificationOptions{
			Checks: checks,
		},
	}

	c.verify(verifyCredentialEndpoint, req, inputData, c.vcHTML, w, r)
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

	req := edgesvcops.VerifyPresentationRequest{
		Presentation: []byte(r.Form.Get(inputData)),
		Opts: &edgesvcops.VerifyPresentationOptions{
			Checks: checks,
		},
	}

	c.verify(verifyPresentationEndpoint, req, inputData, c.vpHTML, w, r)
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

	resp, httpErr := c.client.Post(c.vcsURL+endpoint, httpContentTypeJSON, bytes.NewBuffer(reqBytes))
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
				log.Errorf("closing response body failed: %v", e)
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
		log.Error(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

// writeResponse writes interface value to response
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	log.Error(msg)

	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(verifyVCPath, http.MethodPost, c.verifyVC),
		support.NewHTTPHandler(verifyVPPath, http.MethodPost, c.verifyVP),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}
