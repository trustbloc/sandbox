/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
)

const (
	verifyVC            = "/verifyVC"
	httpContentTypeJSON = "application/json"
	vcsVerifyEndpoint   = "/verify"
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
	vcsURL   string
	client   httpClient
}

// Config defines configuration for rp operations
type Config struct {
	VCHTML string
	VCSURL string
}

// verifyCredentialResponse describes verify credential response
type verifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

// vc struct used to return vc data to html
type vc struct {
	Data string `json:"data"`
}

// New returns rp operation instance
func New(config *Config) *Operation {
	svc := &Operation{
		vcHTML: config.VCHTML, vcsURL: config.VCSURL, client: &http.Client{}}
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

	respData, err := c.httpPost(
		c.vcsURL+vcsVerifyEndpoint, httpContentTypeJSON, []byte(r.Form.Get("vcDataInput")))
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify vc: %s", err.Error()))

		return
	}

	response := verifyCredentialResponse{}
	if errUnmarshal := json.Unmarshal([]byte(respData), &response); errUnmarshal != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal vc: %s", errUnmarshal.Error()))

		return
	}

	if !response.Verified {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify vc: %s", response.Message))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.vcHTML)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Data: r.Form.Get("vcDataInput")}); err != nil {
		log.Error(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) httpPost(url, commContentType string, data []byte) (string, error) {
	resp, err := c.client.Post(url, commContentType, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received unsuccessful POST HTTP status from "+
			"[%s, %v]", url, resp.StatusCode)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			log.Errorf("closing response body failed: %v", e)
		}
	}()

	buf := new(bytes.Buffer)

	_, e := buf.ReadFrom(resp.Body)
	if e != nil {
		return "", e
	}

	return buf.String(), nil
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
	c.handlers = []Handler{support.NewHTTPHandler(verifyVC, http.MethodPost, c.verifyVC)}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}
