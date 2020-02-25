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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const (
	login    = "/login"
	callback = "/callback"
	retrieve = "/retrieve"
	revoke   = "/revoke"

	credentialContext = "https://www.w3.org/2018/credentials/v1"

	vcsUpdateStatusEndpoint = "/updateStatus"

	vcsProfileCookie = "vcsProfile"
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
	receiveVCHTML string
	qrCodeHTML    string
	vcHTML        string
}

// Config defines configuration for issuer operations
type Config struct {
	TokenIssuer   tokenIssuer
	TokenResolver tokenResolver
	CMSURL        string
	VCSURL        string
	ReceiveVCHTML string
	QRCodeHTML    string
	VCHTML        string
}

// vc struct used to return vc data to html
type vc struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
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
		qrCodeHTML:    config.QRCodeHTML,
		receiveVCHTML: config.ReceiveVCHTML,
		vcHTML:        config.VCHTML}
	svc.registerHandler()

	return svc
}

// login using oauth2, will redirect to Auth Code URL
func (c *Operation) login(w http.ResponseWriter, r *http.Request) {
	u := c.tokenIssuer.AuthCodeURL(w)

	scope := r.URL.Query()["scope"]
	if len(scope) > 0 {
		u += "&scope=" + scope[0]
	}

	vcsProfile := r.URL.Query()["vcsProfile"]
	if len(vcsProfile) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("vcs profile is empty"))

		return
	}

	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{Name: vcsProfileCookie, Value: vcsProfile[0], Expires: expire}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// callback for oauth2 login
func (c *Operation) callback(w http.ResponseWriter, r *http.Request) { //nolint: funlen
	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

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

	cred, err := c.createCredential(data, info, vcsProfileCookie.Value)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	err = c.storeCredential(cred, vcsProfileCookie.Value)
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

	q, err := generateQRCode(cred, r.Host)
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate qr code : %s", err.Error()))
		return
	}

	if err := t.Execute(w, q); err != nil {
		log.Error(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

// retrieveVC for retrieving the VC via link and QRCode
func (c *Operation) retrieveVC(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	cred, err := c.retrieveCredential(id, vcsProfileCookie.Value)
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

// revokeVC
func (c *Operation) revokeVC(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse form: %s", err.Error()))

		return
	}

	reqBytes, err := prepareUpdateCredentialStatusRequest(r.Form.Get("vcDataInput"),
		"Revoked", "Disciplinary action")
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to prepare update credential status request: %s", err.Error()))

		return
	}

	req, err := http.NewRequest("POST", c.vcsURL+vcsUpdateStatusEndpoint,
		bytes.NewBuffer(reqBytes))
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create new http request: %s", err.Error()))

		return
	}

	httpClient := http.DefaultClient

	_, err = sendHTTPRequest(req, httpClient, http.StatusOK)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to update vc status: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.vcHTML)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Msg: "VC is revoked", Data: r.Form.Get("vcDataInput")}); err != nil {
		log.Error(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func generateQRCode(cred []byte, host string) (*qr, error) {
	var vcMap map[string]interface{}

	var img []byte

	err := json.Unmarshal(cred, &vcMap)
	if err != nil {
		return nil, fmt.Errorf("generate QR Code unmarshalling failed: %s", err)
	}

	vcID, ok := vcMap["id"].(string)
	if !ok {
		return nil, fmt.Errorf("unable to assert vc ID field type as string")
	}

	retrieveURL := "https://" + host + retrieve + "?" + "id=" + trimQuote(vcID)

	img, err = qrcode.Encode(retrieveURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("generate QR Code encoding failed: %s", err)
	}

	image := base64.StdEncoding.EncodeToString(img)

	return &qr{Image: image, URL: retrieveURL}, nil
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

func (c *Operation) getCMSURL(info *token.Introspection) string {
	// we have only one user for now ...
	userID := "1"

	// scope StudentCard matches studentcards in CMS etc.
	return c.cmsURL + "/" + strings.ToLower(info.Scope) + "s/" + userID
}

func (c *Operation) prepareCreateCredentialRequest(data []byte, info *token.Introspection,
	vcsProfile string) ([]byte, error) {
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
		Context: []string{credentialContext},
		Subject: subject,
		Type:    []string{"VerifiableCredential", info.Scope},
		Profile: vcsProfile,
	}

	return json.Marshal(req)
}

func (c *Operation) createCredential(subject []byte, info *token.Introspection, ledgerType string) ([]byte, error) {
	body, err := c.prepareCreateCredentialRequest(subject, info, ledgerType)

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

func (c *Operation) storeCredential(cred []byte, vcsProfile string) error {
	storeVCBytes, err := prepareStoreVCRequest(cred, vcsProfile)
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

func (c *Operation) retrieveCredential(id, vcsProfile string) ([]byte, error) {
	r, err := http.NewRequest("GET", c.vcsURL+"/retrieve", nil)
	if err != nil {
		return nil, fmt.Errorf("retrieve credential get request failed %s", err)
	}

	q := r.URL.Query()
	q.Add("id", id)
	q.Add("profile", vcsProfile)

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

func prepareUpdateCredentialStatusRequest(cred, status, statusReason string) ([]byte, error) {
	request := updateCredentialStatusRequest{
		Credential:   cred,
		Status:       status,
		StatusReason: statusReason,
	}

	return json.Marshal(request)
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

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.login),
		support.NewHTTPHandler(callback, http.MethodGet, c.callback),
		support.NewHTTPHandler(retrieve, http.MethodGet, c.retrieveVC),
		support.NewHTTPHandler(revoke, http.MethodPost, c.revokeVC),
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
	Context       []string               `json:"@context"`
	Subject       map[string]interface{} `json:"credentialSubject"`
	Type          []string               `json:"type,omitempty"`
	Profile       string                 `json:"profile,omitempty"`
	DID           string                 `json:"did,omitempty"`
	DIDPrivateKey string                 `json:"didPrivateKey,omitempty"`
}

// updateCredentialStatusRequest request struct for updating vc status
type updateCredentialStatusRequest struct {
	Credential   string `json:"credential"`
	Status       string `json:"status"`
	StatusReason string `json:"statusReason"`
}

type storeVC struct {
	Credential string `json:"credential"`
	Profile    string `json:"profile,omitempty"`
}
