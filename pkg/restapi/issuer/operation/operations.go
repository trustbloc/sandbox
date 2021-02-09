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

	"github.com/trustbloc/sandbox/pkg/internal/common/support"
	oidcclient "github.com/trustbloc/sandbox/pkg/restapi/internal/common/oidc"
	"github.com/trustbloc/sandbox/pkg/token"
)

const (
	login                = "/login"
	settings             = "/settings"
	getCreditScore       = "/getCreditScore"
	callback             = "/callback"
	generate             = "/generate"
	revoke               = "/revoke"
	didcommToken         = "/didcomm/token"
	didcommCallback      = "/didcomm/cb"
	didcommCredential    = "/didcomm/data"
	didcommAssuranceData = "/didcomm/assurance"
	oauth2GetRequestPath = "/oauth2/request"
	oauth2CallbackPath   = "/oauth2/callback"

	// http query params
	stateQueryParam = "state"

	credentialContext = "https://www.w3.org/2018/credentials/v1"

	vcsUpdateStatusEndpoint = "/updateStatus"

	vcsProfileCookie     = "vcsProfile"
	demoTypeCookie       = "demoType"
	adapterProfileCookie = "adapterProfile"
	assuranceScopeCookie = "assuranceScope"
	didCommDemo          = "DIDComm"
	nonDIDCommDemo       = "nonDIDComm"

	issueCredentialURLFormat = "%s/%s" + "/credentials/issueCredential"

	// contexts
	trustBlocExampleContext = "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"

	vcsIssuerRequestTokenName = "vcs_issuer"

	// store
	txnStoreName = "issuer_txn"

	scopeQueryParam = "scope"
)

var logger = log.New("sandbox-issuer-restapi")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type oidcClient interface {
	CreateOIDCRequest(state, scope string) (string, error)
	HandleOIDCCallback(reqContext context.Context, code string) ([]byte, error)
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
	didCommVpHTML    string
	httpClient       *http.Client
	requestTokens    map[string]string
	issuerAdapterURL string
	store            storage.Store
	oidcClient       oidcClient
	homePage         string
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
	DIDCOMMVPHTML    string
	TLSConfig        *tls.Config
	RequestTokens    map[string]string
	IssuerAdapterURL string
	StoreProvider    storage.Provider
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCCallbackURL  string
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

type createOIDCRequestResponse struct {
	Request string `json:"request"`
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
		didCommVpHTML:    config.DIDCOMMVPHTML,
		httpClient:       &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:    config.RequestTokens,
		issuerAdapterURL: config.IssuerAdapterURL,
		store:            store,
		homePage:         config.OIDCCallbackURL,
	}

	if config.OIDCProviderURL != "" {
		svc.oidcClient, err = oidcclient.New(&oidcclient.Config{OIDCClientID: config.OIDCClientID,
			OIDCClientSecret: config.OIDCClientSecret, OIDCCallbackURL: config.OIDCCallbackURL,
			OIDCProviderURL: config.OIDCProviderURL, TLSConfig: config.TLSConfig})
		if err != nil {
			return nil, fmt.Errorf("failed to create oidc client : %w", err)
		}
	}

	svc.registerHandler()

	return svc, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.login),
		support.NewHTTPHandler(settings, http.MethodGet, c.settings),
		support.NewHTTPHandler(getCreditScore, http.MethodGet, c.getCreditScore),
		support.NewHTTPHandler(callback, http.MethodGet, c.callback),

		// chapi
		support.NewHTTPHandler(revoke, http.MethodPost, c.revokeVC),
		support.NewHTTPHandler(generate, http.MethodPost, c.generateVC),

		// didcomm
		support.NewHTTPHandler(didcommToken, http.MethodPost, c.didcommTokenHandler),
		support.NewHTTPHandler(didcommCallback, http.MethodGet, c.didcommCallbackHandler),
		support.NewHTTPHandler(didcommCredential, http.MethodPost, c.didcommCredentialHandler),
		support.NewHTTPHandler(didcommAssuranceData, http.MethodPost, c.didcommAssuraceHandler),

		// oidc
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),
	}
}

// login using oauth2, will redirect to Auth Code URL
func (c *Operation) login(w http.ResponseWriter, r *http.Request) {
	u := c.tokenIssuer.AuthCodeURL(w)

	demo := nonDIDCommDemo

	demoType := r.URL.Query()["demoType"]
	if len(demoType) > 0 {
		demo = demoType[0]
	}

	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{Name: demoTypeCookie, Value: demo, Expires: expire}
	http.SetCookie(w, &cookie)

	if demo == nonDIDCommDemo { //nolint:nestif
		if len(r.URL.Query()["vcsProfile"]) == 0 {
			logger.Errorf("vcs profile is empty")
			c.writeErrorResponse(w, http.StatusBadRequest, "vcs profile is empty")

			return
		}

		scope := r.URL.Query()["scope"]
		if len(scope) > 0 {
			u += "&scope=" + scope[0]
		}

		cookie = http.Cookie{Name: vcsProfileCookie, Value: r.URL.Query()["vcsProfile"][0], Expires: expire}
		http.SetCookie(w, &cookie)
	} else {
		if len(r.URL.Query()["adapterProfile"]) == 0 {
			logger.Errorf("adapterProfile profile is empty")
			c.writeErrorResponse(w, http.StatusBadRequest, "adapterProfile profile is empty")

			return
		}

		scope := r.URL.Query()["didCommScope"]
		if len(scope) > 0 {
			u += "&scope=" + scope[0]
		}

		cookie = http.Cookie{Name: adapterProfileCookie, Value: r.URL.Query()["adapterProfile"][0], Expires: expire}
		http.SetCookie(w, &cookie)

		if len(r.URL.Query()["assuranceScope"]) > 0 {
			cookie = http.Cookie{Name: assuranceScopeCookie, Value: r.URL.Query()["assuranceScope"][0], Expires: expire}
			http.SetCookie(w, &cookie)
		}
	}

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func (c *Operation) settings(w http.ResponseWriter, r *http.Request) {
	u := c.homePage

	demo := nonDIDCommDemo

	demoType := r.URL.Query()["demoType"]
	if len(demoType) > 0 {
		demo = demoType[0]
	}

	expire := time.Now().AddDate(0, 0, 1)

	if demo == nonDIDCommDemo {
		if len(r.URL.Query()["vcsProfile"]) == 0 {
			logger.Errorf("vcs profile is empty")
			c.writeErrorResponse(w, http.StatusBadRequest, "vcs profile is empty")

			return
		}

		cookie := http.Cookie{Name: vcsProfileCookie, Value: r.URL.Query()["vcsProfile"][0], Expires: expire}
		http.SetCookie(w, &cookie)
	}

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// callback for oauth2 login
func (c *Operation) callback(w http.ResponseWriter, r *http.Request) { //nolint: funlen,gocyclo
	if len(r.URL.Query()["error"]) != 0 {
		if r.URL.Query()["error"][0] == "access_denied" {
			http.Redirect(w, r, c.homePage, http.StatusTemporaryRedirect)
		}
	}

	demoTypeCookie, err := r.Cookie(demoTypeCookie)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get demoType cookie: %s", err.Error()))

		return
	}

	tk, err := c.tokenIssuer.Exchange(r)
	if err != nil {
		logger.Errorf("failed to exchange code for token: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to exchange code for token: %s", err.Error()))

		return
	}

	// user info from token will be used for to retrieve data from cms
	info, err := c.tokenResolver.Resolve(tk.AccessToken)
	if err != nil {
		logger.Errorf("failed to get token info: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get token info: %s", err.Error()))

		return
	}

	userID, subject, err := c.getCMSData(tk, "email="+info.Subject, info.Scope)
	if err != nil {
		logger.Errorf("failed to get cms data: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	if demoTypeCookie != nil && demoTypeCookie.Value == didCommDemo {
		c.didcomm(w, r, userID, subject, "")

		return
	}

	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		logger.Errorf("failed to get cookie: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	cred, err := c.prepareCredential(subject, info, vcsProfileCookie.Value)
	if err != nil {
		logger.Errorf("failed to create credential: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.didAuthHTML)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, map[string]interface{}{
		"Path": generate + "?" + "profile=" + vcsProfileCookie.Value,
		"Cred": string(cred),
	}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

func (c *Operation) getCreditScore(w http.ResponseWriter, r *http.Request) {
	userID, subject, err := c.getCMSData(nil, "name="+url.QueryEscape(r.URL.Query()["givenName"][0]+" "+
		r.URL.Query()["familyName"][0]), r.URL.Query()["didCommScope"][0])
	if err != nil {
		logger.Errorf("failed to get cms data: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	c.didcomm(w, r, userID, subject, r.URL.Query()["adapterProfile"][0])
}

func (c *Operation) createOIDCRequest(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get(scopeQueryParam)
	if scope == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing scope")

		return
	}

	// TODO validate scope
	state := uuid.New().String()

	redirectURL, err := c.oidcClient.CreateOIDCRequest(state, scope)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to create oidc request : %s", err))

		return
	}

	response, err := json.Marshal(&createOIDCRequestResponse{
		Request: redirectURL,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal response : %s", err))

		return
	}

	err = c.store.Put(state, []byte(state))
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

func (c *Operation) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
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

	_, err := c.store.Get(state)
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

	data, err := c.oidcClient.HandleOIDCCallback(r.Context(), code)
	if err != nil {
		logger.Errorf("failed to handle oidc callback : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to handle oidc callback: %s", err))

		return
	}

	c.didcommDemoResult(w, string(data))
}

func (c *Operation) didcommDemoResult(w http.ResponseWriter, data string) {
	t, err := template.ParseFiles(c.didCommVpHTML)
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

// generateVC for creates VC
//nolint: funlen
func (c *Operation) generateVC(w http.ResponseWriter, r *http.Request) {
	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		logger.Errorf("failed to get vcsProfileCookie: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cookie: %s", err.Error()))

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
		logger.Errorf("failed to create verifiable credential: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create verifiable credential: %s", err.Error()))

		return
	}

	err = c.storeCredential(cred, vcsProfileCookie.Value)
	if err != nil {
		logger.Errorf("failed to store credential: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store credential: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.receiveVCHTML)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Data: string(cred)}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

// revokeVC
func (c *Operation) revokeVC(w http.ResponseWriter, r *http.Request) { //nolint: funlen,gocyclo
	if err := r.ParseForm(); err != nil {
		logger.Errorf("failed to parse form: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse form: %s", err.Error()))

		return
	}

	vp, err := verifiable.ParsePresentation([]byte(r.Form.Get("vcDataInput")),
		verifiable.WithPresDisabledProofCheck())
	if err != nil {
		logger.Errorf("failed to parse presentation: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse presentation: %s", err.Error()))

		return
	}

	creds := make([]json.RawMessage, 0)

	for _, cred := range vp.Credentials() {
		cre, ok := cred.(map[string]interface{})
		if !ok {
			logger.Errorf("failed to cast credential")
			c.writeErrorResponse(w, http.StatusInternalServerError, "failed to cast credential")

			return
		}

		credBytes, errMarshal := json.Marshal(cre)
		if errMarshal != nil {
			logger.Errorf("failed to marshal credentials: %s", errMarshal.Error())
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to marshal credentials: %s", errMarshal.Error()))

			return
		}

		creds = append(creds, credBytes)
	}

	reqBytes, err := prepareUpdateCredentialStatusRequest(creds)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to prepare update credential status request: %s", err.Error()))

		return
	}

	req, err := http.NewRequest("POST", c.vcsURL+vcsUpdateStatusEndpoint,
		bytes.NewBuffer(reqBytes))
	if err != nil {
		logger.Errorf("failed to create new http request: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create new http request: %s", err.Error()))

		return
	}

	_, err = sendHTTPRequest(req, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		logger.Errorf("failed to update vc status: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to update vc status: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	t, err := template.ParseFiles(c.vcHTML)
	if err != nil {
		logger.Errorf("unable to load html: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, vc{Msg: "VC is revoked", Data: r.Form.Get("vcDataInput")}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) didcomm(w http.ResponseWriter, r *http.Request, userID string, subjectData map[string]interface{},
	issuerID string) {
	if issuerID == "" {
		adapterProfileCookie, err := r.Cookie(adapterProfileCookie)
		if err != nil {
			logger.Errorf("failed to get adapterProfileCookie: %s", err.Error())
			c.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("failed to get adapterProfileCookie: %s", err.Error()))

			return
		}

		issuerID = adapterProfileCookie.Value
	}

	subjectDataBytes, err := json.Marshal(subjectData)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store state subject mapping : %s", err.Error()))
		return
	}

	assuranceScopeCookie, err := r.Cookie(assuranceScopeCookie)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get assuranceScopeCookie: %s",
			err.Error()))

		return
	}

	userData := userDataMap{
		ID:   userID,
		Data: subjectDataBytes,
	}

	if assuranceScopeCookie != nil {
		userData.AssuranceScope = assuranceScopeCookie.Value
	}

	userDataBytes, err := json.Marshal(userData)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal data : %s", err.Error()))

		return
	}

	state := uuid.New().String()

	err = c.store.Put(state, userDataBytes)
	if err != nil {
		logger.Errorf("failed to store state subject mapping : %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store state subject mapping : %s", err.Error()))

		return
	}

	logger.Infof("didcomm user data : state=%s data=%s", state, string(userDataBytes))

	http.Redirect(w, r, fmt.Sprintf(c.issuerAdapterURL+"/%s/connect/wallet?state=%s", issuerID, state), http.StatusFound)
}

func (c *Operation) didcommTokenHandler(w http.ResponseWriter, r *http.Request) {
	data := &adapterTokenReq{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		logger.Errorf("invalid request : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	cred, err := c.store.Get(data.State)
	if err != nil {
		logger.Errorf("invalid state : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid state : %s", err.Error()))

		return
	}

	tkn := uuid.New().String()

	err = c.store.Put(tkn, cred)
	if err != nil {
		logger.Errorf("failed to store adapter token and userID mapping : %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store adapter token and userID mapping : %s", err.Error()))

		return
	}

	userInfo := userDataMap{}

	err = json.Unmarshal(cred, &userInfo)
	if err != nil {
		logger.Errorf("failed to unmarshal user state info : %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to read user state info : %s", err.Error()))

		return
	}

	resp := adapterTokenResp{
		Token:  tkn,
		UserID: userInfo.ID,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store adapter token and userID mapping : %s", err.Error()))
		return
	}

	c.writeResponse(w, http.StatusOK, respBytes)

	logger.Infof("didcomm flow token creation : token:%s credential=%s", string(respBytes), string(cred))
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

	logger.Infof("didcomm callback handler success")
}

func (c *Operation) didcommCredentialHandler(w http.ResponseWriter, r *http.Request) {
	data := &adapterDataReq{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		logger.Errorf("invalid request : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	userDataBytes, err := c.store.Get(data.Token)
	if err != nil {
		logger.Errorf("failed to get token data : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get token data : %s", err.Error()))

		return
	}

	var userData userDataMap

	err = json.Unmarshal(userDataBytes, &userData)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("user data unmarshal failed: %s", err.Error()))

		return
	}

	logger.Infof("didcomm flow get user data : token:%s credential=%s", data.Token, string(userData.Data))

	c.writeResponse(w, http.StatusOK, userData.Data)
}

func (c *Operation) didcommAssuraceHandler(w http.ResponseWriter, r *http.Request) {
	data := &adapterDataReq{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		logger.Errorf("invalid request : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err.Error()))

		return
	}

	// make sure token exists
	userDataBytes, err := c.store.Get(data.Token)
	if err != nil {
		logger.Errorf("failed to get token data : %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get token data : %s", err.Error()))

		return
	}

	var userData userDataMap

	err = json.Unmarshal(userDataBytes, &userData)
	if err != nil {
		logger.Errorf("user data unmarshal failed : %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("user data unmarshal failed : %s", err.Error()))

		return
	}

	assuranceData, err := c.getAssuracneData(userData.AssuranceScope, userData.ID)
	if err != nil {
		logger.Errorf("failed to get assurance data : %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get assurance data : %s", err.Error()))

		return
	}

	dataBytes, err := json.Marshal(assuranceData)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal assurance data : %s", err.Error()))

		return
	}

	logger.Infof("didcomm flow get assurance data : token:%s credential=%s", data.Token, string(dataBytes))

	c.writeResponse(w, http.StatusOK, dataBytes)
}

func (c *Operation) getAssuracneData(assuranceScope, userID string) (map[string]interface{}, error) {
	u := c.cmsURL + "/" + assuranceScope + "s?userid=" + userID

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	subjectBytes, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, "")
	if err != nil {
		return nil, err
	}

	return unmarshalSubject(subjectBytes)
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

	_, err = c.store.Get(state)
	if err != nil {
		return fmt.Errorf("invalid state : %s", err)
	}

	// TODO https://github.com/trustbloc/sandbox/issues/493 validate token existence for the state

	return nil
}

func (c *Operation) getCMSUser(tk *oauth2.Token, searchQuery string) (*cmsUser, error) {
	userURL := c.cmsURL + "/users?" + searchQuery

	httpClient := c.httpClient
	if tk != nil {
		httpClient = c.tokenIssuer.Client(tk)
	}

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

func (c *Operation) retrieveProfile(profileName string) (*vcprofile.IssuerProfile, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(c.vcsURL+"/profile/%s", profileName), nil)
	if err != nil {
		return nil, err
	}

	respBytes, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		return nil, err
	}

	profileResponse := &vcprofile.IssuerProfile{}

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

	if subject, ok := credential.Subject.([]verifiable.Subject); ok && len(subject) > 0 {
		subject[0].ID = holder
	} else {
		return nil, errors.New("invalid credential subject")
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
	vp, err := verifiable.ParsePresentation(authResp, verifiable.WithPresDisabledProofCheck())
	if err != nil {
		return err
	}

	if vp.Holder != holder {
		return fmt.Errorf("invalid auth response, invalid holder proof")
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

func prepareUpdateCredentialStatusRequest(creds []json.RawMessage) ([]byte, error) {
	request := edgesvcops.UpdateCredentialStatusRequest{
		Credentials: creds,
	}

	return json.Marshal(request)
}

func (c *Operation) getCMSData(tk *oauth2.Token, searchQuery, scope string) (string, map[string]interface{}, error) {
	userID, subjectBytes, err := c.getUserData(tk, searchQuery, scope)
	if err != nil {
		return "", nil, err
	}

	subjectMap, err := unmarshalSubject(subjectBytes)
	if err != nil {
		return "", nil, err
	}

	return userID, subjectMap, nil
}

func (c *Operation) getUserData(tk *oauth2.Token, searchQuery, scope string) (string, []byte, error) {
	user, err := c.getCMSUser(tk, searchQuery)
	if err != nil {
		return "", nil, err
	}

	// scope StudentCard matches studentcards in CMS etc.
	u := c.cmsURL + "/" + strings.ToLower(scope) + "s?userid=" + user.UserID

	httpClient := c.httpClient
	if tk != nil {
		httpClient = c.tokenIssuer.Client(tk)
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", nil, err
	}

	respBytes, err := sendHTTPRequest(req, httpClient, http.StatusOK, "")
	if err != nil {
		return "", nil, err
	}

	return user.UserID, respBytes, nil
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

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw http.ResponseWriter, status int, data []byte) {
	rw.WriteHeader(status)

	if _, err := rw.Write(data); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func getTxnStore(prov storage.Provider) (storage.Store, error) {
	err := prov.CreateStore(txnStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, err
	}

	txnStore, err := prov.OpenStore(txnStoreName)
	if err != nil {
		return nil, err
	}

	return txnStore, nil
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

type adapterTokenReq struct {
	State string `json:"state,omitempty"`
}

// IssuerTokenResp issuer user data token response.
type adapterTokenResp struct {
	Token  string `json:"token,omitempty"`
	UserID string `json:"userid"`
}

type userDataMap struct {
	ID             string          `json:"id,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	AssuranceScope string          `json:"assuranceScope,omitempty"`
}
