/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const (
	login    = "/login"
	callback = "/callback"
	retrieve = "/retrieve"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers for authorization service
type Operation struct {
	handlers      []Handler
	tokenIssuer   tokenIssuer
	tokenResolver tokenResolver
	cmsURL        string
	vcsURL        string
	vcsProfile    string
	receiveVCHTML string
	qrCodeHTML    string
}

// Config defines configuration for issuer operations
type Config struct {
	TokenIssuer   tokenIssuer
	TokenResolver tokenResolver
	CMSURL        string
	VCSURL        string
	VCSProfile    string
	QRCodeHTML    string
	ReceiveVCHTML string
}

// vc struct used to return vc data to html
type vc struct {
	Data interface{} `json:"data"`
}

type qr struct {
	Image string
	URL   string
}

type tokenIssuer interface {
	AuthCodeURL(w http.ResponseWriter) string
	Exchange(r *http.Request) (*oauth2.Token, error)
	Client(ctx context.Context, t *oauth2.Token) *http.Client
}

type tokenResolver interface {
	Resolve(token string) (*token.Introspection, error)
}

// New returns authorization instance
func New(config *Config) *Operation {
	svc := &Operation{
		tokenIssuer:   config.TokenIssuer,
		tokenResolver: config.TokenResolver,
		cmsURL:        config.CMSURL,
		vcsURL:        config.VCSURL,
		vcsProfile:    config.VCSProfile,
		qrCodeHTML:    config.QRCodeHTML,
		receiveVCHTML: config.ReceiveVCHTML}
	svc.registerHandler()

	return svc
}

// Login using oauth2, will redirect to Auth Code URL
func (c *Operation) Login(w http.ResponseWriter, r *http.Request) {
	u := c.tokenIssuer.AuthCodeURL(w)

	scope := r.URL.Query()["scope"]
	if len(scope) > 0 {
		u += "&scope=" + scope[0]
	}

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// Callback for oauth2 login
func (c *Operation) Callback(w http.ResponseWriter, r *http.Request) {
	tk, err := c.tokenIssuer.Exchange(r)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to exchange code for token: %s", err.Error()))

		return
	}

	// user info from token will be used for to retrieve data from cms
	info, err := c.tokenResolver.Resolve(tk.AccessToken)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get token info: %s", err.Error()))

		return
	}

	data, err := c.getCMSData(tk, info)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get user cms data: %s", err.Error()))

		return
	}

	cred, err := c.createCredential(data, info)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	err = c.storeCredential(cred)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to store credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.qrCodeHTML)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	q, err := generateQRCode(cred, r.URL.Host)
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate qr code : %s", err.Error()))
		return
	}

	if err := t.Execute(w, q); err != nil {
		log.Error(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

// RetrieveVC for retrieving the VC via link and QRCode
func (c *Operation) RetrieveVC(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	cred, err := c.retrieveCredential(id)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.receiveVCHTML)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	// retrieve credential returns the strings with back slashes, to render the response as string without slashes
	cr, err := strconv.Unquote(string(cred))
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("unable to unqote credential: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Data: cr}); err != nil {
		log.Error(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func generateQRCode(cred []byte, host string) (*qr, error) {
	var subject map[string]interface{}

	var img []byte

	err := json.Unmarshal(cred, &subject)
	if err != nil {
		return nil, fmt.Errorf("generate QR Code unmarshalling failed: %s", err)
	}

	// credential ID, id is interface
	id := subject["id"]

	credIDBytes, err := json.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("generate QR Code marshalling failed: %s", err)
	}

	retrieveURL := host + retrieve + "?" + "id=" + trimQuote(string(credIDBytes))

	img, err = qrcode.Encode(retrieveURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("generate QR Code encoding failed: %s", err)
	}

	image := base64.StdEncoding.EncodeToString(img)

	return &qr{Image: image, URL: retrieveURL}, nil
}

func (c *Operation) getCMSURL(info *token.Introspection) string {
	// we have only one user for now ...
	userID := "1"

	// scope StudentCard matches studentcards in CMS etc.
	return c.cmsURL + "/" + strings.ToLower(info.Scope) + "s/" + userID
}

func (c *Operation) prepareCreateCredentialRequest(data []byte, info *token.Introspection) ([]byte, error) {
	var subject map[string]interface{}

	err := json.Unmarshal(data, &subject)
	if err != nil {
		return nil, err
	}

	// remove cms id, add name as id (will be replaced by DID)
	subject["id"] = subject["name"]

	// remove cms specific fields
	delete(subject, "created_at")
	delete(subject, "updated_at")

	req := &createCredential{
		Subject: subject,
		Type:    []string{"VerifiableCredential", info.Scope},
		Profile: c.vcsProfile,
	}

	return json.Marshal(req)
}

func (c *Operation) createCredential(subject []byte, info *token.Introspection) ([]byte, error) {
	body, err := c.prepareCreateCredentialRequest(subject, info)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.vcsURL+"/credential", bytes.NewBuffer(body))

	if err != nil {
		return nil, err
	}

	httpClient := http.DefaultClient

	return sendHTTPRequest(req, httpClient, http.StatusCreated)
}

func (c *Operation) storeCredential(cred []byte) error {
	storeVCBytes, err := prepareStoreVCRequest(cred, c.vcsProfile)
	if err != nil {
		return err
	}

	storeReq, err := http.NewRequest("POST", c.vcsURL+"/store", bytes.NewBuffer(storeVCBytes))

	if err != nil {
		return err
	}

	httpClient := http.DefaultClient

	_, err = sendHTTPRequest(storeReq, httpClient, http.StatusOK)
	if err != nil {
		return err
	}

	return nil
}

func (c *Operation) retrieveCredential(id string) ([]byte, error) {
	r, err := http.NewRequest("GET", c.vcsURL+"/retrieve", nil)
	if err != nil {
		return nil, fmt.Errorf("retrieve credential get request failed %s", err)
	}

	q := r.URL.Query()
	q.Add("id", id)
	q.Add("profile", c.vcsProfile)

	r.URL.RawQuery = q.Encode()

	httpClient := http.DefaultClient

	return sendHTTPRequest(r, httpClient, http.StatusOK)
}

func prepareStoreVCRequest(cred []byte, profile string) ([]byte, error) {
	storeVCRequest := storeVC{
		Credential: string(cred),
		Profile:    profile,
	}

	return json.Marshal(storeVCRequest)
}

func (c *Operation) getCMSData(tk *oauth2.Token, info *token.Introspection) ([]byte, error) {
	url := c.getCMSURL(info)

	httpClient := c.tokenIssuer.Client(context.Background(), tk)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return sendHTTPRequest(req, httpClient, http.StatusOK)
}

func sendHTTPRequest(req *http.Request, client *http.Client, status int) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Warn("failed to close response body")
		}
	}()

	if resp.StatusCode != status {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warnf("failed to read response body for status: %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}

func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}

	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}

	return s
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.Login),
		support.NewHTTPHandler(callback, http.MethodGet, c.Callback),
		support.NewHTTPHandler(retrieve, http.MethodGet, c.RetrieveVC),
	}
}

// writeResponse writes interface value to response
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

// createCredential input data for edge service issuer rest api
type createCredential struct {
	Subject map[string]interface{} `json:"credentialSubject"`
	Type    []string               `json:"type,omitempty"`
	Profile string                 `json:"profile,omitempty"`
}

type storeVC struct {
	Credential string `json:"credential"`
	Profile    string `json:"profile,omitempty"`
}
