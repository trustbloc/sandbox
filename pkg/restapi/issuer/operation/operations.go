/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const (
	login    = "/login"
	callback = "/callback"
	generate = "/generate"
	retrieve = "/retrieve"
	revoke   = "/revoke"

	credentialContext = "https://www.w3.org/2018/credentials/v1"

	vcsUpdateStatusEndpoint = "/updateStatus"

	vcsProfileCookie = "vcsProfile"

	issueCredentialURLFormat = "%s/%s" + "/credentials/issueCredential"

	// contexts
	trustBlocExampleContext = "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
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
	didAuthHTML   string
	vcHTML        string
	httpClient    *http.Client
}

// Config defines configuration for issuer operations
type Config struct {
	TokenIssuer   tokenIssuer
	TokenResolver tokenResolver
	CMSURL        string
	VCSURL        string
	ReceiveVCHTML string
	QRCodeHTML    string
	DIDAuthHTML   string
	VCHTML        string
	TLSConfig     *tls.Config
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
	Client(t *oauth2.Token) *http.Client
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
		didAuthHTML:   config.DIDAuthHTML,
		receiveVCHTML: config.ReceiveVCHTML,
		vcHTML:        config.VCHTML,
		httpClient:    &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}}}
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

	subject, err := c.getCMSData(tk, info)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	cred, err := c.prepareCredential(subject, info, vcsProfileCookie.Value)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.didAuthHTML)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, map[string]interface{}{
		"Path": generate + "?" + "profile=" + vcsProfileCookie.Value,
		"Cred": string(cred),
	}); err != nil {
		log.Error(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

// generateVC for creates VC
func (c *Operation) generateVC(w http.ResponseWriter, r *http.Request) {
	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to parse request form: %s", err.Error()))

		return
	}

	err = c.validateForm(r.Form, "cred", "holder", "authresp")
	if err != nil {
		log.Errorf("invalid generate credential request: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request argument: %s", err.Error()))

		return
	}

	cred, err := c.createCredential(r.Form["cred"][0], r.Form["authresp"][0], r.Form["holder"][0], vcsProfileCookie.Value)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create verifiable credentiall: %s", err.Error()))

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

	q, err := generateQRCode(cred, r.Host, vcsProfileCookie.Value)
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
	profile := r.URL.Query().Get("profile")

	cred, err := c.retrieveCredential(id, profile)
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

	if err := t.Execute(w, vc{Data: string(cred)}); err != nil {
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

	_, err = sendHTTPRequest(req, c.httpClient, http.StatusOK)
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

func generateQRCode(cred []byte, host, profile string) (*qr, error) {
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

	retrieveURL := "https://" + host + retrieve + "?" + "profile=" + profile + "&" + "id=" + trimQuote(vcID)

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

func (c *Operation) getCMSUser(tk *oauth2.Token, info *token.Introspection) (*cmsUser, error) {
	userURL := c.cmsURL + "/users?email=" + info.Subject

	httpClient := c.tokenIssuer.Client(tk)

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	userBytes, err := sendHTTPRequest(req, httpClient, http.StatusOK)
	if err != nil {
		return nil, err
	}

	return unmarshalUser(userBytes)
}

func unmarshalUser(userBytes []byte) (*cmsUser, error) {
	var users []cmsUser

	err := json.Unmarshal(userBytes, &users)
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, errors.New("user not found")
	}

	if len(users) > 1 {
		return nil, errors.New("multiple users found")
	}

	return &users[0], nil
}

func unmarshalSubject(data []byte) (map[string]interface{}, error) {
	var subjects []map[string]interface{}

	err := json.Unmarshal(data, &subjects)
	if err != nil {
		return nil, err
	}

	if len(subjects) == 0 {
		return nil, errors.New("record not found")
	}

	if len(subjects) > 1 {
		return nil, errors.New("multiple records found")
	}

	return subjects[0], nil
}

func (c *Operation) prepareCredential(subject map[string]interface{}, info *token.Introspection,
	vcsProfile string) ([]byte, error) {
	// remove cms id, add name as id (will be replaced by DID)
	subject["id"] = subject["name"]
	subject["type"] = info.Scope

	// remove cms specific fields
	delete(subject, "created_at")
	delete(subject, "updated_at")
	delete(subject, "userid")

	profileResponse, err := c.retrieveProfile(vcsProfile)
	if err != nil {
		return nil, fmt.Errorf("retrieve profile - name=%s err=%s", vcsProfile, err)
	}

	issueDate := time.Now().UTC()

	cred := &verifiable.Credential{}
	cred.Context = []string{credentialContext, trustBlocExampleContext}
	cred.Subject = subject
	cred.Types = []string{"VerifiableCredential", info.Scope}
	cred.Issued = &issueDate
	cred.Issuer.ID = profileResponse.DID
	cred.Issuer.Name = profileResponse.Name
	cred.ID = profileResponse.URI + "/" + uuid.New().String()

	return json.Marshal(cred)
}

func (c *Operation) retrieveProfile(profileName string) (*vcprofile.DataProfile, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(c.vcsURL+"/profile/%s", profileName), nil)
	if err != nil {
		return nil, err
	}

	respBytes, err := sendHTTPRequest(req, c.httpClient, http.StatusOK)
	if err != nil {
		return nil, err
	}

	profileResponse := &vcprofile.DataProfile{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}

func (c *Operation) createCredential(cred, authResp, holder, id string) ([]byte, error) { //nolint: lll
	// currently using only holder from authResp
	// TODO need to validate proof in authResp??
	if holder == "" || !strings.Contains(authResp, fmt.Sprintf(`"%s"`, holder)) {
		return nil, fmt.Errorf("credential subject id is not matching with DID auth response")
	}

	credential, _, err := verifiable.NewCredential([]byte(cred), verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %w", err)
	}

	if subject, ok := credential.Subject.(map[string]interface{}); ok {
		subject["id"] = holder
	}

	credBytes, err := credential.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential bytes: %w", err)
	}

	body, err := json.Marshal(edgesvcops.IssueCredentialRequest{
		Credential: credBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential")
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, c.vcsURL, id)

	req, err := http.NewRequest("POST", endpointURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	return sendHTTPRequest(req, c.httpClient, http.StatusCreated)
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

	_, err = sendHTTPRequest(storeReq, c.httpClient, http.StatusOK)
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

	return sendHTTPRequest(r, c.httpClient, http.StatusOK)
}

func (c *Operation) validateForm(formVals url.Values, keys ...string) error {
	for _, key := range keys {
		if _, found := getFormValue(key, formVals); !found {
			return fmt.Errorf("invalid '%s'", key)
		}
	}

	return nil
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

func (c *Operation) getCMSData(tk *oauth2.Token, info *token.Introspection) (map[string]interface{}, error) {
	user, err := c.getCMSUser(tk, info)
	if err != nil {
		return nil, err
	}

	// scope StudentCard matches studentcards in CMS etc.
	u := c.cmsURL + "/" + strings.ToLower(info.Scope) + "s?userid=" + user.UserID

	httpClient := c.tokenIssuer.Client(tk)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	subjectBytes, err := sendHTTPRequest(req, httpClient, http.StatusOK)
	if err != nil {
		return nil, err
	}

	return unmarshalSubject(subjectBytes)
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

// getFormValue reads form url value by key
func getFormValue(k string, vals url.Values) (string, bool) {
	if cr, ok := vals[k]; ok && len(cr) > 0 {
		return cr[0], true
	}

	return "", false
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.login),
		support.NewHTTPHandler(callback, http.MethodGet, c.callback),
		support.NewHTTPHandler(retrieve, http.MethodGet, c.retrieveVC),
		support.NewHTTPHandler(revoke, http.MethodPost, c.revokeVC),
		support.NewHTTPHandler(generate, http.MethodPost, c.generateVC),
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

type cmsUser struct {
	UserID string `json:"userid"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}
