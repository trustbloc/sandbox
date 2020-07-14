/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/tls"
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/issuer/operation"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const (
	login             = "/login"
	callback          = "/callback"
	generate          = "/generate"
	revoke            = "/revoke"
	didcommCallback   = "/didcomm/cb"
	didcommCredential = "/didcomm/credential"

	// http query params
	stateQueryParam = "state"
	tokenQueryParam = "token"

	credentialContext = "https://www.w3.org/2018/credentials/v1"

	vcsUpdateStatusEndpoint = "/updateStatus"

	vcsProfileCookie = "vcsProfile"
	demoTypeCookie   = "demoType"
	didCommDemo      = "DIDComm"

	issueCredentialURLFormat = "%s/%s" + "/credentials/issueCredential"

	// contexts
	trustBlocExampleContext = "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"

	vcsIssuerRequestTokenName = "vcs_issuer"

	// store
	txnStoreName = "issuer_txn"
)

var logger = log.New("edge-sandbox-issuer-restapi")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers for authorization service
type Operation struct {
	handlers         []Handler
	tokenIssuer      tokenIssuer
	tokenResolver    tokenResolver
	cmsURL           string
	vcsURL           string
	receiveVCHTML    string
	didAuthHTML      string
	vcHTML           string
	didCommHTML      string
	httpClient       *http.Client
	requestTokens    map[string]string
	issuerAdapterURL string
	store            storage.Store
}

// Config defines configuration for issuer operations
type Config struct {
	TokenIssuer      tokenIssuer
	TokenResolver    tokenResolver
	CMSURL           string
	VCSURL           string
	ReceiveVCHTML    string
	DIDAuthHTML      string
	VCHTML           string
	DIDCommHTML      string
	TLSConfig        *tls.Config
	RequestTokens    map[string]string
	IssuerAdapterURL string
	StoreProvider    storage.Provider
}

// vc struct used to return vc data to html
type vc struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
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
func New(config *Config) (*Operation, error) {
	store, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, fmt.Errorf("issuer store provider : %w", err)
	}

	svc := &Operation{
		tokenIssuer:      config.TokenIssuer,
		tokenResolver:    config.TokenResolver,
		cmsURL:           config.CMSURL,
		vcsURL:           config.VCSURL,
		didAuthHTML:      config.DIDAuthHTML,
		receiveVCHTML:    config.ReceiveVCHTML,
		vcHTML:           config.VCHTML,
		didCommHTML:      config.DIDCommHTML,
		httpClient:       &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:    config.RequestTokens,
		issuerAdapterURL: config.IssuerAdapterURL,
		store:            store,
	}
	svc.registerHandler()

	return svc, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.login),
		support.NewHTTPHandler(callback, http.MethodGet, c.callback),

		// chapi
		support.NewHTTPHandler(revoke, http.MethodPost, c.revokeVC),
		support.NewHTTPHandler(generate, http.MethodPost, c.generateVC),

		// didcomm
		support.NewHTTPHandler(didcommCallback, http.MethodGet, c.didcommCallbackHandler),
		support.NewHTTPHandler(didcommCredential, http.MethodPost, c.didcommCredentialHandler),
	}
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
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("vcs profile is empty"))

		return
	}

	demo := "nonDIDComm"

	demoType := r.URL.Query()["demoType"]
	if len(demoType) > 0 {
		demo = demoType[0]
	}

	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{Name: vcsProfileCookie, Value: vcsProfile[0], Expires: expire}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{Name: demoTypeCookie, Value: demo, Expires: expire}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// callback for oauth2 login
func (c *Operation) callback(w http.ResponseWriter, r *http.Request) { //nolint: funlen,gocyclo
	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	demoTypeCookie, err := r.Cookie(demoTypeCookie)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get demoType cookie: %s", err.Error()))

		return
	}

	tk, err := c.tokenIssuer.Exchange(r)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to exchange code for token: %s", err.Error()))

		return
	}

	// user info from token will be used for to retrieve data from cms
	info, err := c.tokenResolver.Resolve(tk.AccessToken)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get token info: %s", err.Error()))

		return
	}

	subject, err := c.getCMSData(tk, info)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	cred, err := c.prepareCredential(subject, info, vcsProfileCookie.Value)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	if demoTypeCookie != nil && demoTypeCookie.Value == didCommDemo {
		c.didcomm(w, r, cred, vcsProfileCookie.Value)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.didAuthHTML)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, map[string]interface{}{
		"Path": generate + "?" + "profile=" + vcsProfileCookie.Value,
		"Cred": string(cred),
	}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

// generateVC for creates VC
//nolint: funlen
func (c *Operation) generateVC(w http.ResponseWriter, r *http.Request) {
	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	err = r.ParseForm()
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to parse request form: %s", err.Error()))

		return
	}

	err = c.validateForm(r.Form, "cred", "holder", "authresp", "domain", "challenge")
	if err != nil {
		logger.Errorf("invalid generate credential request: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request argument: %s", err.Error()))

		return
	}

	cred, err := c.createCredential(r.Form["cred"][0], r.Form["authresp"][0], r.Form["holder"][0],
		r.Form["domain"][0], r.Form["challenge"][0], vcsProfileCookie.Value)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create verifiable credential: %s", err.Error()))

		return
	}

	err = c.storeCredential(cred, vcsProfileCookie.Value)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to store credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.receiveVCHTML)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Data: string(cred)}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
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

	_, err = sendHTTPRequest(req, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
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
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) didcomm(w http.ResponseWriter, r *http.Request, cred []byte, profileID string) {
	// TODO https://github.com/trustbloc/edge-sandbox/issues/391 configure DIDComm Issuers
	issuerID := "tb-cc-issuer"

	signedVC, err := c.issueCredential(cred, profileID)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to issue credential : %s", err.Error()))

		return
	}

	state := uuid.New().String()

	err = c.store.Put(state, signedVC)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store state subject mapping : %s", err.Error()))

		return
	}

	http.Redirect(w, r, fmt.Sprintf(c.issuerAdapterURL+"/%s/connect/wallet?state=%s", issuerID, state), http.StatusFound)
}

func (c *Operation) didcommCallbackHandler(w http.ResponseWriter, r *http.Request) {
	err := c.validateAdapterCallback(r.URL.RequestURI())
	if err != nil {
		logger.Errorf("failed to validate the adapter response: %s", err)
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to validate the adapter response: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.didCommHTML)
	if err != nil {
		logger.Errorf("unable to load didcomm html: %s", err)
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load didcomm html: %s", err.Error()))

		return
	}

	err = t.Execute(w, map[string]interface{}{})
	if err != nil {
		logger.Errorf(fmt.Sprintf("failed execute didcomm html template: %s", err.Error()))
	}
}

func (c *Operation) didcommCredentialHandler(w http.ResponseWriter, r *http.Request) {
	data := &adapterDataReq{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	cred, err := c.store.Get(data.Token)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid token: %s", err.Error()))

		return
	}

	w.WriteHeader(http.StatusOK)

	_, err = w.Write(cred)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write data: %s", err.Error()))

		return
	}
}

func (c *Operation) issueCredential(credBytes []byte, profileID string) ([]byte, error) {
	body, err := json.Marshal(edgesvcops.IssueCredentialRequest{
		Credential: credBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential : %w", err)
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, c.vcsURL, profileID)

	req, err := http.NewRequest("POST", endpointURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	return sendHTTPRequest(req, c.httpClient, http.StatusCreated, c.requestTokens[vcsIssuerRequestTokenName])
}

func (c *Operation) validateAdapterCallback(redirectURL string) error {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return fmt.Errorf("didcomm callback - error parsing the request url: %s", err)
	}

	state := u.Query().Get(stateQueryParam)
	if state == "" {
		return errors.New("missing state in http query param")
	}

	tkn := u.Query().Get(tokenQueryParam)
	if tkn == "" {
		return errors.New("missing token in http query param")
	}

	cred, err := c.store.Get(state)
	if err != nil {
		return fmt.Errorf("invalid state : %s", err)
	}

	err = c.store.Put(tkn, cred)
	if err != nil {
		return fmt.Errorf("store adapter token and userID mapping : %s", err)
	}

	return nil
}

func (c *Operation) getCMSUser(tk *oauth2.Token, info *token.Introspection) (*cmsUser, error) {
	userURL := c.cmsURL + "/users?email=" + info.Subject

	httpClient := c.tokenIssuer.Client(tk)

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	userBytes, err := sendHTTPRequest(req, httpClient, http.StatusOK, "")
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
	// will be replaced by DID auth response subject ID
	subject["id"] = ""

	vcContext := []string{credentialContext, trustBlocExampleContext}
	customFields := make(map[string]interface{})
	// get custom vc data if available
	if m, ok := subject["vcmetadata"]; ok {
		if vcMetaData, ok := m.(map[string]interface{}); ok {
			vcContext = getCustomContext(vcContext, vcMetaData)
			customFields["name"] = vcMetaData["name"]
			customFields["description"] = vcMetaData["description"]
		}
	}

	// remove cms specific fields
	delete(subject, "created_at")
	delete(subject, "updated_at")
	delete(subject, "userid")
	delete(subject, "vcmetadata")

	profileResponse, err := c.retrieveProfile(vcsProfile)
	if err != nil {
		return nil, fmt.Errorf("retrieve profile - name=%s err=%s", vcsProfile, err)
	}

	cred := &verifiable.Credential{}
	cred.Context = vcContext
	cred.Subject = subject
	cred.Types = []string{"VerifiableCredential", info.Scope}
	cred.Issued = util.NewTime(time.Now().UTC())
	cred.Issuer.ID = profileResponse.DID
	cred.Issuer.CustomFields = make(verifiable.CustomFields)
	cred.Issuer.CustomFields["name"] = profileResponse.Name
	cred.ID = profileResponse.URI + "/" + uuid.New().String()
	cred.CustomFields = customFields

	// credential subject as single json entity in CMS for complex data
	if s, ok := subject["vccredentialsubject"]; ok {
		if subject, ok := s.(map[string]interface{}); ok {
			cred.Subject = subject
		}
	}

	return json.Marshal(cred)
}

func getCustomContext(existingContext []string, customCtx map[string]interface{}) []string {
	if ctx, found := customCtx["@context"]; found {
		var result []string
		for _, v := range ctx.([]interface{}) {
			result = append(result, v.(string))
		}

		return result
	}

	return existingContext
}

func (c *Operation) retrieveProfile(profileName string) (*vcprofile.DataProfile, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(c.vcsURL+"/profile/%s", profileName), nil)
	if err != nil {
		return nil, err
	}

	respBytes, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
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

func (c *Operation) createCredential(cred, authResp, holder, domain, challenge, id string) ([]byte, error) { //nolint: lll
	err := c.validateAuthResp([]byte(authResp), holder, domain, challenge)
	if err != nil {
		return nil, fmt.Errorf("DID Auth failed: %w", err)
	}

	credential, err := verifiable.ParseCredential([]byte(cred), verifiable.WithDisabledProofCheck())
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

	return sendHTTPRequest(req, c.httpClient, http.StatusCreated, c.requestTokens[vcsIssuerRequestTokenName])
}

// validateAuthResp validates did auth response against given domain and challenge
func (c *Operation) validateAuthResp(authResp []byte, holder, domain, challenge string) error {
	vp, err := verifiable.ParsePresentation(authResp)
	if err != nil {
		return err
	}

	if vp.Holder != holder {
		return fmt.Errorf("invalid auth response, invalid holder proof")
	}

	if len(vp.Proofs) == 0 {
		return fmt.Errorf("invalid auth response, missing proof")
	}

	proofOfInterest := vp.Proofs[0]

	var proofChallenge, proofDomain string

	if c, ok := proofOfInterest["challenge"]; ok && c != nil {
		//nolint: errcheck
		proofChallenge = c.(string)
	} else {
		return fmt.Errorf("invalid auth response proof, missing challenge")
	}

	if d, ok := proofOfInterest["domain"]; ok && d != nil {
		//nolint: errcheck
		proofDomain = d.(string)
	} else {
		return fmt.Errorf("invalid auth response proof, missing domain")
	}

	if proofChallenge != challenge || proofDomain != domain {
		return fmt.Errorf("invalid proof and challenge in response")
	}

	return nil
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

	_, err = sendHTTPRequest(storeReq, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		return err
	}

	return nil
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

	subjectBytes, err := sendHTTPRequest(req, httpClient, http.StatusOK, "")
	if err != nil {
		return nil, err
	}

	return unmarshalSubject(subjectBytes)
}

func sendHTTPRequest(req *http.Request, client *http.Client, status int, httpToken string) ([]byte, error) {
	if httpToken != "" {
		req.Header.Add("Authorization", "Bearer "+httpToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	if resp.StatusCode != status {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
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

// writeResponse writes interface value to response
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(txnStoreName)
	if err != nil && err != storage.ErrDuplicateStore {
		return nil, err
	}

	txnStore, err := prov.OpenStore(txnStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
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

type adapterDataReq struct {
	Token string `json:"token"`
}
