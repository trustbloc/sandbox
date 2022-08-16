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
	"sort"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	compclient "github.com/trustbloc/ace/pkg/client/comparator/client"
	compclientops "github.com/trustbloc/ace/pkg/client/comparator/client/operations"
	compmodel "github.com/trustbloc/ace/pkg/client/comparator/models"
	vaultclient "github.com/trustbloc/ace/pkg/client/vault"
	"github.com/trustbloc/ace/pkg/restapi/comparator/operation/models"
	"github.com/trustbloc/ace/pkg/restapi/vault"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edv/pkg/edvutils"
	edgesvcops "github.com/trustbloc/vcs/pkg/restapi/issuer/operation"

	"github.com/trustbloc/sandbox/pkg/internal/common/support"
)

const (
	// api paths
	register            = "/register"
	login               = "/login"
	logout              = "/logout"
	connect             = "/connect"
	link                = "/link"
	accountLinkCallback = "/callback"
	consent             = "/consent"
	client              = "/client"
	getClient           = client + "/{id}"
	profile             = "/profile"
	getProfile          = profile + "/{id}"
	users               = "/users"
	userAuth            = users + "/auth"
	generateUserAuth    = userAuth + "/generate"
	userExtract         = users + "/extract"
	getUserExtract      = userExtract + "/{id}"

	// store
	txnStoreName      = "issuer_txn"
	userStoreName     = "user_txn"
	userAuthStoreName = "userauth_txn"

	// form param
	username   = "username"
	password   = "password"
	nationalID = "nationalID"

	// cookies
	actionCookie     = "action"
	idCookie         = "id"
	linkAction       = "link"
	sessionidCookie  = "sessionid"
	cookieExpiryTime = 5
	authExpiryTime   = 5
	// TODO- this should be configurable
	resultLimit = 5

	vcsIssuerRequestTokenName = "vcs_issuer"
	requestTimeout            = 30 * time.Second
	userIDLen                 = 7

	// external paths
	issueCredentialURLFormat = "%s" + "/credentials/issue"
	accountLinkURLFormat     = "%s/link?client_id=%s&callback=%s/callback&state=%s"

	// json-ld
	credentialContext = "https://www.w3.org/2018/credentials/v1"

	nationalIDVCPath = "$.credentialSubject." + nationalID

	userTagName = "user"
)

var logger = log.New("ace-rp-restapi")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vaultClient interface {
	CreateVault() (*vault.CreatedVault, error)
	SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error)
	CreateAuthorization(vaultID, requestingParty string,
		scope *vault.AuthorizationsScope) (*vault.CreatedAuthorization, error)
}

type comparatorClient interface {
	GetConfig(params *compclientops.GetConfigParams,
		opts ...compclientops.ClientOption) (*compclientops.GetConfigOK, error)
	PostAuthorizations(params *compclientops.PostAuthorizationsParams,
		opts ...compclientops.ClientOption) (*compclientops.PostAuthorizationsOK, error)
	PostCompare(params *compclientops.PostCompareParams,
		opts ...compclientops.ClientOption) (*compclientops.PostCompareOK, error)
	PostExtract(params *compclientops.PostExtractParams,
		opts ...compclientops.ClientOption) (*compclientops.PostExtractOK, error)
}

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers.
type Operation struct {
	store                storage.Store
	userStore            storage.Store
	userAuthStore        storage.Store
	handlers             []Handler
	homePageHTML         string
	loginHTML            string
	dashboardHTML        string
	consentHTML          string
	accountLinkedHTML    string
	accountNotLinkedHTML string
	httpClient           httpClient
	vcIssuerURL          string
	requestTokens        map[string]string
	accountLinkProfile   string
	extractorProfile     string
	hostExternalURL      string
	vClient              vaultClient
	compClient           comparatorClient
	svcName              string
	vdri                 vdrapi.Registry
	documentLoader       ld.DocumentLoader
}

// Config config.
type Config struct {
	StoreProvider        storage.Provider
	HomePageHTML         string
	LoginHTML            string
	DashboardHTML        string
	ConsentHTML          string
	AccountLinkedHTML    string
	AccountNotLinkedHTML string
	TLSConfig            *tls.Config
	VaultServerURL       string
	ComparatorURL        string
	VCIssuerURL          string
	AccountLinkProfile   string
	ExtractorProfile     string
	HostExternalURL      string
	RequestTokens        map[string]string
	SvcName              string
	VDRI                 vdrapi.Registry
	DocumentLoader       ld.DocumentLoader
}

// New returns ace-rp operation instance.
func New(config *Config) (*Operation, error) {
	store, err := getStore(config.StoreProvider, txnStoreName, nil)
	if err != nil {
		return nil, fmt.Errorf("ace-rp store provider : %w", err)
	}

	userStore, err := getStore(config.StoreProvider, userStoreName,
		&storage.StoreConfiguration{TagNames: []string{userTagName}})
	if err != nil {
		return nil, fmt.Errorf("ace-rp userStore store provider : %w", err)
	}

	userAuthStore, err := getStore(config.StoreProvider, userAuthStoreName,
		&storage.StoreConfiguration{TagNames: []string{userTagName}})
	if err != nil {
		return nil, fmt.Errorf("ace-rp userAuthStore store provider : %w", err)
	}

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}}

	if config.ComparatorURL == "" {
		return nil, errors.New("comparator url mandatory")
	}

	comparatorURL := strings.Split(config.ComparatorURL, "://")

	transport := httptransport.NewWithClient(
		comparatorURL[1],
		compclient.DefaultBasePath,
		[]string{comparatorURL[0]},
		httpClient,
	)

	op := &Operation{
		store:                store,
		userStore:            userStore,
		userAuthStore:        userAuthStore,
		homePageHTML:         config.HomePageHTML,
		loginHTML:            config.LoginHTML,
		dashboardHTML:        config.DashboardHTML,
		consentHTML:          config.ConsentHTML,
		httpClient:           httpClient,
		accountLinkedHTML:    config.AccountLinkedHTML,
		accountNotLinkedHTML: config.AccountNotLinkedHTML,
		vcIssuerURL:          config.VCIssuerURL,
		accountLinkProfile:   config.AccountLinkProfile,
		extractorProfile:     config.ExtractorProfile,
		hostExternalURL:      config.HostExternalURL,
		requestTokens:        config.RequestTokens,
		vClient:              vaultclient.New(config.VaultServerURL, vaultclient.WithHTTPClient(httpClient)),
		compClient:           compclient.New(transport, strfmt.Default).Operations,
		svcName:              config.SvcName,
		vdri:                 config.VDRI,
		documentLoader:       config.DocumentLoader,
	}

	op.registerHandler()

	return op, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (o *Operation) registerHandler() {
	o.handlers = []Handler{
		support.NewHTTPHandler(register, http.MethodPost, o.register),
		support.NewHTTPHandler(login, http.MethodPost, o.login),
		support.NewHTTPHandler(logout, http.MethodGet, o.logout),
		support.NewHTTPHandler(connect, http.MethodGet, o.connect),
		support.NewHTTPHandler(link, http.MethodGet, o.link),
		support.NewHTTPHandler(accountLinkCallback, http.MethodGet, o.accountLinkCallback),
		support.NewHTTPHandler(consent, http.MethodGet, o.consent),
		support.NewHTTPHandler(client, http.MethodPost, o.createClient),
		support.NewHTTPHandler(getClient, http.MethodGet, o.getClient),
		support.NewHTTPHandler(profile, http.MethodPost, o.createProfile),
		support.NewHTTPHandler(getProfile, http.MethodGet, o.getProfile),
		support.NewHTTPHandler(getProfile, http.MethodDelete, o.deleteProfile),
		support.NewHTTPHandler(users, http.MethodGet, o.getUsers),
		support.NewHTTPHandler(generateUserAuth, http.MethodPost, o.generateUserAuths),
		support.NewHTTPHandler(userAuth, http.MethodPost, o.saveUserAuths),
		support.NewHTTPHandler(userExtract, http.MethodGet, o.extractRequests),
		support.NewHTTPHandler(getUserExtract, http.MethodGet, o.getUserExtract),

		// TODO find a way to handle this in start.go
		support.NewHTTPHandler("/showlogin", http.MethodGet, o.showlogin),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return o.handlers
}

func (o *Operation) register(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	err := r.ParseForm()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	pwd, err := o.store.Get(r.FormValue(username))
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to get user data %s : %s", r.FormValue(username), err.Error()))

		return
	}

	if pwd != nil {
		w.WriteHeader(http.StatusBadRequest)
		o.showDashboard(w, r.FormValue(username),
			fmt.Sprintf("Username '%s' already exists", r.FormValue(username)), "", false)

		return
	}

	// create vault for the user
	vaultID, docID, err := o.storeNationalID(r.FormValue(nationalID))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store national id in vault %s - err:%s", r.FormValue(nationalID), err.Error()))

		return
	}

	uData := userData{
		ID:              strings.ToUpper(uniuri.NewLen(userIDLen)),
		UserName:        r.FormValue(username),
		VaultID:         vaultID,
		NationalIDDocID: docID,
	}

	uDataBytes, err := json.Marshal(uData)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal user data - err:%s", err.Error()))

		return
	}

	err = o.store.Put(r.FormValue(username), uDataBytes)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to save user data %s: %s", r.FormValue(username), err.Error()))

		return
	}

	uMap := userIDNameMap{
		ID:          uData.ID,
		UserName:    uData.UserName,
		CreatedTime: util.NewTime(time.Now()),
	}

	uMapBytes, err := json.Marshal(uMap)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal user data - err:%s", err.Error()))

		return
	}

	err = o.userStore.Put(uData.ID, uMapBytes, storage.Tag{Name: userTagName})
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to save id-username mapping data: %s", err.Error()))

		return
	}

	o.showDashboard(w, r.FormValue(username), "", vaultID, false)
}

func (o *Operation) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	uData, err := o.getUserData(r.FormValue(username))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to get user data %s: %s", r.FormValue(username), err.Error()))

		return
	}

	action := ""
	id := ""

	if r.URL.Query() != nil {
		actionParam := r.URL.Query()["action"]
		if len(actionParam) != 0 {
			action = actionParam[0]
		}

		idParam := r.URL.Query()["id"]
		if len(idParam) != 0 {
			id = idParam[0]

			logger.Warnf("id=%s", id)
		}

		logger.Infof("loginQueryParam: action=%s id=%s", action, id)
	}

	sessionID := uuid.New().String()

	err = o.store.Put(sessionID, []byte(r.FormValue(username)))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to save session : %s", err.Error()))

		return
	}

	if action == linkAction {
		o.loadHTML(w, o.consentHTML, map[string]interface{}{
			"QueryParam": fmt.Sprintf("?action=%s&id=%s&sessionid=%s", action, id, sessionID),
		})

		return
	}

	o.showDashboard(w, r.FormValue(username), "", uData.VaultID, true)
}

func (o *Operation) showlogin(w http.ResponseWriter, r *http.Request) {
	clearCookies(w)

	o.loadHTML(w, o.loginHTML, map[string]interface{}{"QueryParam": ""})
}

func (o *Operation) logout(w http.ResponseWriter, r *http.Request) {
	clearCookies(w)

	o.loadHTML(w, o.homePageHTML, map[string]interface{}{})
}

func (o *Operation) connect(w http.ResponseWriter, r *http.Request) {
	userName := r.URL.Query()["userName"]
	if len(userName) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing username")

		return
	}

	data, err := o.getProfileData(o.accountLinkProfile)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get profile data : %s", err.Error()))

		return
	}

	state := uuid.New().String()

	err = o.store.Put(state, []byte(userName[0]))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to save state data : %s", err.Error()))
		return
	}

	endpoint := fmt.Sprintf(accountLinkURLFormat, data.URL, data.ClientID, o.hostExternalURL, state)

	logger.Infof("connect: redirectURL=[%s]", endpoint)

	// TODO https://github.com/trustbloc/sandbox/issues/808 use OIDC to get auth token for account comparison

	http.Redirect(w, r, endpoint, http.StatusFound)
}

func (o *Operation) accountLinkCallback(w http.ResponseWriter, r *http.Request) { // nolint: funlen,  gocyclo
	auth := r.URL.Query()["auth"]
	if len(auth) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing authorization")
		o.loadHTML(w, o.accountNotLinkedHTML, nil)

		return
	}

	state := r.URL.Query()["state"]
	if len(state) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing state")

		return
	}

	uNameBytes, err := o.store.Get(state[0])
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get state %s : %s", state, err.Error()))

		return
	}

	userData, err := o.getUserData(string(uNameBytes))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to get user data: %s", err.Error()))

		return
	}

	confResp, err := o.compClient.GetConfig(compclientops.NewGetConfigParams().
		WithTimeout(requestTimeout))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed get config from comparator: %s", err.Error()))

		return
	}

	if confResp.Payload == nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "empty config from comparator")

		return
	}

	docAuth, err := o.vClient.CreateAuthorization(
		userData.VaultID,
		confResp.Payload.AuthKeyURL,
		&vault.AuthorizationsScope{
			Target:  userData.NationalIDDocID,
			Actions: []string{"read"},
			Caveats: []vault.Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: uint64(authExpiryTime * time.Second)}},
		},
	)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create vault authorization: %s", err.Error()))

		return
	}

	if docAuth == nil || docAuth.Tokens == nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "missing auth token from vault-server")

		return
	}

	logger.Infof("compare : vaultID=[%s] docID=[%s] kmsToken=[%s] edvToken=[%s] auth=[%s]",
		userData.VaultID, userData.NationalIDDocID, docAuth.Tokens.KMS, docAuth.Tokens.EDV, auth[0])

	query := make([]models.Query, 0)
	query = append(query,
		&models.DocQuery{
			DocID:       &userData.NationalIDDocID,
			VaultID:     &userData.VaultID,
			AuthTokens:  &models.DocQueryAO1AuthTokens{Kms: docAuth.Tokens.KMS, Edv: docAuth.Tokens.EDV},
			DocAttrPath: nationalIDVCPath,
		},
		&models.AuthorizedQuery{
			AuthToken: &auth[0],
		},
	)

	eq := &models.EqOp{}
	eq.SetArgs(query)

	cr := &compmodel.Comparison{}
	cr.SetOp(eq)

	compareResp, err := o.compClient.PostCompare(
		compclientops.NewPostCompareParams().
			WithTimeout(requestTimeout).
			WithComparison(cr),
	)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to compare docs: %s", err.Error()))

		return
	}

	if compareResp.Payload == nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "missing compare result from comparator")

		return
	}

	logger.Infof("compare: result=[%s]", compareResp.Payload.Result)

	if !compareResp.Payload.Result {
		o.loadHTML(w, o.accountNotLinkedHTML, nil)

		return
	}

	o.loadHTML(w, o.accountLinkedHTML, nil)
}

func (o *Operation) link(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query()["client_id"]
	if len(clientID) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing client_id")

		return
	}

	callback := r.URL.Query()["callback"]
	if len(callback) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing callback url")

		return
	}

	state := r.URL.Query()["state"]
	if len(state) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing state")

		return
	}

	logger.Infof("link : clientID=[%s] callbackURL=[%s] state=[%s]", clientID, callback, state)

	cData, err := o.getClientData(clientID[0])
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get client data: %s", err.Error()))

		return
	}

	data := sessionData{
		State:       state[0],
		CallbackURL: callback[0],
		DID:         cData.DID,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal session data: %s", err.Error()))

		return
	}

	sessionid := uuid.New().String()

	err = o.store.Put(sessionid, dataBytes)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to save session data: %s", err.Error()))

		return
	}

	o.loadHTML(w, o.loginHTML, map[string]interface{}{
		"QueryParam": fmt.Sprintf("?action=%s&id=%s", linkAction, sessionid),
	})
}

// nolint: funlen
func (o *Operation) consent(w http.ResponseWriter, r *http.Request) { // nolint: gocyclo
	id := ""
	sessionID := ""

	if r.URL.Query() != nil {
		idParam := r.URL.Query()["id"]
		if len(idParam) != 0 {
			id = idParam[0]
		}

		sessionIDParam := r.URL.Query()["sessionid"]
		if len(sessionIDParam) != 0 {
			sessionID = sessionIDParam[0]
		}

		logger.Infof("consentQueryParam: id=%s sessionID=%s", id, sessionID)
	}

	if id == "" || sessionID == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "sessionid or id can't be empty")

		return
	}

	username, err := o.store.Get(sessionID)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get session data: %s", err.Error()))

		return
	}

	userData, err := o.getUserData(string(username))
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get user data: %s", err.Error()))

		return
	}

	// get the session data from db
	dataBytes, err := o.store.Get(id)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get state data: %s", err.Error()))

		return
	}

	var data *sessionData

	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal state data: %s", err.Error()))

		return
	}

	compConfig, err := o.getComparatorConfig()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed get config from comparator: %s", err.Error()))

		return
	}

	// pass the zcap to the caller
	auth, err := o.getAuthorization(
		userData.VaultID,
		compConfig.AuthKeyURL,
		userData.NationalIDDocID,
		data.DID,
	)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed create authorization : %s", err.Error()))

		return
	}

	// invalid the cookies
	clearCookies(w)

	redirectURL := fmt.Sprintf("%s?state=%s&auth=%s", data.CallbackURL, data.State, auth)

	logger.Infof("consent : redirectURL=%s", redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (o *Operation) createClient(w http.ResponseWriter, r *http.Request) {
	req := &clientReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	data := clientData{
		ClientID: uuid.New().String(),
		DID:      req.DID,
		Callback: req.Callback,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal client data: %s", err.Error()))

		return
	}

	err = o.store.Put(data.ClientID, dataBytes)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to save client data: %s", err.Error()))

		return
	}

	o.writeResponse(w, http.StatusCreated, clientResp{
		ClientID:     data.ClientID,
		ClientSecret: uuid.New().String(),
		DID:          req.DID,
		Callback:     req.Callback,
	})
}

func (o *Operation) getClient(w http.ResponseWriter, r *http.Request) {
	var data *clientData

	o.getData(w, strings.Split(r.URL.Path, "/")[2], data)
}

func (o *Operation) createProfile(w http.ResponseWriter, r *http.Request) {
	data := &profileData{}

	err := json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal client data: %s", err.Error()))

		return
	}

	err = o.store.Put(data.ID, dataBytes)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to save client data: %s", err.Error()))

		return
	}

	o.writeResponse(w, http.StatusCreated, data)
}

func (o *Operation) getProfile(w http.ResponseWriter, r *http.Request) {
	var data *profileData

	o.getData(w, strings.Split(r.URL.Path, "/")[2], data)
}

func (o *Operation) getData(w http.ResponseWriter, id string, data interface{}) {
	dataBytes, err := o.store.Get(id)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get data : id=%s - %s", id, err.Error()))

		return
	}

	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal data : id=%s - %s", id, err.Error()))

		return
	}

	o.writeResponse(w, http.StatusOK, data)
}

func (o *Operation) deleteProfile(w http.ResponseWriter, r *http.Request) {
	profileID := strings.Split(r.URL.Path, "/")[2]

	err := o.store.Delete(profileID)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to delete data : id=%s - %s", profileID, err.Error()))

		return
	}

	o.writeResponse(w, http.StatusOK, nil)
}

func (o *Operation) getUsers(w http.ResponseWriter, r *http.Request) {
	u, err := o.fetchUsers()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed get user data: %s", err.Error()))

		return
	}

	// send the user data in the response
	o.writeResponse(w, http.StatusOK, &getUserDataResp{Users: u})
}

func (o *Operation) generateUserAuths(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	data := &generateUserAuthReq{}

	err := json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	// get all the users
	u, err := o.fetchUsers(data.Users...)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed get user data: %s", err.Error()))

		return
	}

	// validate profile
	pData, err := o.getProfileData(o.extractorProfile)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get profile data: %s", err.Error()))

		return
	}

	// get the comparator config
	compConfig, err := o.getComparatorConfig()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed get config from comparator: %s", err.Error()))

		return
	}

	userAuths := make([]userAuthorization, 0)

	// get the authorization for all
	for _, v := range u {
		logger.Infof("generateUserAuths: id=[%s] vaultID=[%s] nationalDocID=[%s]", v.ID, v.VaultID, v.NationalIDDocID)
		// pass the zcap to the caller
		auth, authErr := o.getAuthorization(
			v.VaultID,
			compConfig.AuthKeyURL,
			v.NationalIDDocID,
			pData.DID,
		)
		if authErr != nil {
			o.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed create authorization : %s", authErr.Error()))

			return
		}

		userAuths = append(userAuths, userAuthorization{ID: v.ID, Name: v.UserName, DID: v.VaultID, AuthToken: auth})
	}

	uData := &userAuthData{
		Source:        o.svcName,
		SubmittedTime: util.NewTime(time.Now()),
		UserAuths:     userAuths,
	}

	reqBytes, err := json.Marshal(uData)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal request to extractor service : %s", err.Error()))

		return
	}

	// post the user authorizations to the extractor service
	endpoint := pData.Callback + userAuth

	_, err = o.sendHTTPRequest(http.MethodPost, endpoint, reqBytes, http.StatusOK, "")
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get user auth data : %s", err.Error()))

		return
	}

	// send the authorizations in the response
	o.writeResponse(w, http.StatusOK, uData)
}

func (o *Operation) saveUserAuths(w http.ResponseWriter, r *http.Request) {
	// decode request
	data := &userAuthData{}

	err := json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	if len(data.UserAuths) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "no user auths in the request")

		return
	}

	// create a new id and save the data
	data.ID = uuid.NewString()

	authBytes, err := json.Marshal(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to marshal user auth data: %s", err.Error()))

		return
	}

	err = o.userAuthStore.Put(data.ID, authBytes, storage.Tag{Name: userTagName})
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to save user auth data: %s", err.Error()))

		return
	}

	logger.Infof("saveUserAuths: id=[%s] data=[%s]", data.ID, string(authBytes))

	// send response
	o.writeResponse(w, http.StatusOK, map[string]string{"id": data.ID})
}

func (o *Operation) extractRequests(w http.ResponseWriter, r *http.Request) {
	userAuthData, err := o.fetchUserAuths()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get user auth data: %s", err.Error()))

		return
	}

	eData := make([]extractData, 0)

	for _, authData := range userAuthData {
		eData = append(eData, extractData{
			ID:            authData.ID,
			Source:        authData.Source,
			SubmittedTime: authData.SubmittedTime,
		})
	}

	// send response
	o.writeResponse(w, http.StatusOK, extractResp{ExtractData: eData})
}

func (o *Operation) getUserExtract(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	id := strings.Split(r.URL.Path, "/")[3]

	userAuthDataByte, err := o.userAuthStore.Get(id)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get user auth data %s : %s", id, err.Error()))

		return
	}

	var u *userAuthData

	err = json.Unmarshal(userAuthDataByte, &u)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to unmarshal user auth data %s : %s", string(userAuthDataByte), err.Error()))

		return
	}

	queries := make([]compmodel.Query, 0)
	queryMap := make(map[string]string)

	for _, auths := range u.UserAuths {
		queryID := uuid.NewString()

		t := auths.AuthToken

		query := &compmodel.AuthorizedQuery{AuthToken: &t}
		query.SetID(queryID)

		queries = append(queries, query)
		queryMap[queryID] = auths.ID

		logger.Infof("extractUserData: id=[%s] name=[%s] queryID=[%s] token=[%s]",
			auths.ID, auths.Name, query.ID(), *query.AuthToken)
	}

	request := &compmodel.Extract{}
	request.SetQueries(queries)

	extractRes, err := o.compClient.PostExtract(
		compclientops.NewPostExtractParams().WithTimeout(requestTimeout).WithExtract(request),
	)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to extract data: %s", err))

		return
	}

	if len(extractRes.Payload.Documents) != len(queries) {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("count of documents %d doesnt match the expected %d",
				len(extractRes.Payload.Documents), len(queries)))

		return
	}

	userNationalIDMap := make(map[string]string)

	for _, k := range extractRes.Payload.Documents {
		logger.Infof("extract: id=%s content=%v type=%T", k.ID, k.Contents, k.Contents)

		nationalID, ok := k.Contents.(string)
		if !ok {
			o.writeErrorResponse(w, http.StatusInternalServerError, "invalid content; expected string type")

			return
		}

		userNationalIDMap[queryMap[k.ID]] = nationalID
	}

	uData := make([]userExtractedData, 0)

	for _, auths := range u.UserAuths {
		uData = append(uData, userExtractedData{
			ID:         auths.ID,
			Name:       auths.Name,
			DID:        auths.DID,
			NationalID: userNationalIDMap[auths.ID],
		})
	}

	// send response
	o.writeResponse(w, http.StatusOK, getExtractData{
		Data: uData,
	})
}

func (o *Operation) showDashboard(w http.ResponseWriter, userName, errMsg, vaultID string, serviceLinked bool) {
	endpoint := fmt.Sprintf("/connect?userName=%s", userName)
	if serviceLinked {
		endpoint = fmt.Sprintf("/disconnect?userName=%s", userName)
	}

	if errMsg == "" {
		o.loadHTML(w, o.dashboardHTML, map[string]interface{}{
			"UserName":      userName,
			"ServiceLinked": serviceLinked,
			"URL":           endpoint,
			"VaultID":       vaultID,
			"ErrMsg":        "",
		})
	} else {
		o.loadHTML(w, o.homePageHTML, map[string]interface{}{
			"UserName":      userName,
			"ServiceLinked": serviceLinked,
			"URL":           endpoint,
			"ErrMsg":        errMsg,
		})
	}
}

func (o *Operation) loadHTML(w http.ResponseWriter, htmlFileName string, data map[string]interface{}) {
	t, err := template.ParseFiles(htmlFileName)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err := t.Execute(w, data); err != nil {
		logger.Errorf("failed execute %s html template: %s", htmlFileName, err.Error())
	}
}

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	logger.Errorf(msg)

	rw.WriteHeader(status)

	write := rw.Write
	if _, err := write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

func (o *Operation) writeResponse(rw http.ResponseWriter, status int, v interface{}) {
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to send response, %s", err)
	}
}

func (o *Operation) getUserData(username string) (*userData, error) {
	uDataBytes, err := o.store.Get(username)
	if err != nil {
		return nil, fmt.Errorf("get user data: %w", err)
	}

	var uData *userData

	err = json.Unmarshal(uDataBytes, &uData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal user data: %w", err)
	}

	return uData, nil
}

func (o *Operation) getClientData(clientID string) (*clientData, error) {
	cDataBytes, err := o.store.Get(clientID)
	if err != nil {
		return nil, fmt.Errorf("get client data: %w", err)
	}

	var cData *clientData

	err = json.Unmarshal(cDataBytes, &cData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal client data: %w", err)
	}

	return cData, nil
}

func (o *Operation) getProfileData(profileID string) (*profileData, error) {
	dataBytes, err := o.store.Get(profileID)
	if err != nil {
		return nil, fmt.Errorf("get profile data: %w", err)
	}

	var data *profileData

	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("unamrshal profile data: %w", err)
	}

	return data, nil
}

func (o *Operation) fetchUsers(ids ...string) ([]userData, error) {
	var usernamesToFetch []string

	if len(ids) == 0 {
		allUsernames, err := o.getAllUsernames()
		if err != nil {
			return nil, fmt.Errorf("failed to get all usernames: %w", err)
		}

		usernamesToFetch = allUsernames
	} else {
		usernamesToFetch = make([]string, 0)

		userData, err := o.userStore.GetBulk(ids...)
		if err != nil {
			return nil, fmt.Errorf("get all user data: %w", err)
		}

		for _, v := range userData {
			var u *userIDNameMap

			err = json.Unmarshal(v, &u)
			if err != nil {
				return nil, fmt.Errorf("unamrshal user data %s : %w", string(v), err)
			}

			usernamesToFetch = append(usernamesToFetch, u.UserName)
		}
	}

	logger.Infof("usernamesToFetch=%s", usernamesToFetch)

	if len(usernamesToFetch) > 0 {
		bulkData, err := o.store.GetBulk(usernamesToFetch...)
		if err != nil {
			return nil, fmt.Errorf("get user data keys=%s : %w", usernamesToFetch, err)
		}

		users := make([]userData, len(bulkData))

		for i, v := range bulkData {
			var u userData

			err = json.Unmarshal(v, &u)
			if err != nil {
				return nil, fmt.Errorf("unamrshal user data %s: %w", string(v), err)
			}

			users[i] = u
		}

		return users, nil
	}

	return make([]userData, 0), nil
}

func (o *Operation) getAllUsernames() ([]string, error) {
	userIDNames := make([]userIDNameMap, 0)

	userDataIterator, err := o.userStore.Query("user")
	if err != nil {
		return nil, fmt.Errorf("get all user data: %w", err)
	}

	moreUserData, err := userDataIterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next user's data: %w", err)
	}

	for moreUserData {
		userDataValue, err := userDataIterator.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get user data value: %w", err)
		}

		var u *userIDNameMap

		err = json.Unmarshal(userDataValue, &u)
		if err != nil {
			return nil, fmt.Errorf("unamrshal user data %s : %w", string(userDataValue), err)
		}

		userIDNames = append(userIDNames, *u)

		moreUserData, err = userDataIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next user's data: %w", err)
		}
	}

	sort.Slice(userIDNames, func(i, j int) bool {
		return userIDNames[i].CreatedTime.After(userIDNames[j].CreatedTime.Time)
	})

	// TODO configure this limit value
	if len(userIDNames) > resultLimit {
		userIDNames = userIDNames[:resultLimit]
	}

	userNames := make([]string, 0)

	for _, v := range userIDNames {
		userNames = append(userNames, v.UserName)
	}

	return userNames, nil
}

func (o *Operation) fetchUserAuths() ([]userAuthData, error) {
	users := make([]userAuthData, 0)

	userDataIterator, err := o.userAuthStore.Query("user")
	if err != nil {
		return nil, fmt.Errorf("get all user auth data: %w", err)
	}

	moreUserData, err := userDataIterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next user auth data: %w", err)
	}

	for moreUserData {
		userDataValue, err := userDataIterator.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get user auth data value: %w", err)
		}

		var u *userAuthData

		err = json.Unmarshal(userDataValue, &u)
		if err != nil {
			return nil, fmt.Errorf("unamrshal user auth data %s : %w", string(userDataValue), err)
		}

		users = append(users, *u)

		moreUserData, err = userDataIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next user's data: %w", err)
		}
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].SubmittedTime.After(users[j].SubmittedTime.Time)
	})

	// TODO configure this limit value
	if len(users) > resultLimit {
		users = users[:resultLimit]
	}

	return users, nil
}

func (o *Operation) storeNationalID(id string) (string, string, error) {
	vaultData, err := o.vClient.CreateVault()
	if err != nil {
		return "", "", fmt.Errorf("create vault : %w", err)
	}

	vaultID := vaultData.ID

	// wrap nationalID in a vc
	vc, err := o.createNationalIDCred(vaultID, id)
	if err != nil {
		return "", "", fmt.Errorf("create vc for nationalID : %w", err)
	}

	// resolve DID
	err = resolveDID(o.vdri, vaultID, 10)
	if err != nil {
		return "", "", fmt.Errorf("resolve did %s : %w", vaultID, err)
	}

	// save nationalID vc
	docID, err := o.saveNationalIDDoc(
		vaultID,
		vc,
	)
	if err != nil {
		return "", "", fmt.Errorf("save nationalID doc : %w", err)
	}

	logger.Infof("storeNationalID : vaultID=[%s] docID=[%s] content=[%s]", vaultID, docID, vc)

	return vaultID, docID, nil
}

func (o *Operation) createNationalIDCred(sub, id string) (*verifiable.Credential, error) {
	if id == "" {
		return nil, errors.New("nationalID is mandatory")
	}

	cred := verifiable.Credential{}
	cred.ID = uuid.New().URN()
	cred.Context = []string{credentialContext}
	cred.Types = []string{"VerifiableCredential"}
	// issuerID will be overwritten in the issuer
	cred.Issuer = verifiable.Issuer{ID: uuid.New().URN()}
	cred.Issued = util.NewTime(time.Now().UTC())

	credentialSubject := make(map[string]interface{})
	credentialSubject["id"] = sub
	credentialSubject[nationalID] = id

	cred.Subject = credentialSubject

	credBytes, err := cred.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}

	vcReq, err := json.Marshal(edgesvcops.IssueCredentialRequest{
		Credential: credBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vc request credential: %w", err)
	}

	endpoint := fmt.Sprintf(issueCredentialURLFormat, o.vcIssuerURL)

	vcResp, err := o.sendHTTPRequest(http.MethodPost, endpoint, vcReq, http.StatusCreated,
		o.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		return nil, fmt.Errorf("failed to create vc - url:%s err: %w", endpoint, err)
	}

	vc, err := verifiable.ParseCredential(vcResp, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("parse vc : %w", err)
	}

	return vc, nil
}

func (o *Operation) saveNationalIDDoc(vaultID string, vc interface{}) (string, error) {
	docID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return "", fmt.Errorf("create edv doc id : %w", err)
	}

	_, err = o.vClient.SaveDoc(vaultID, docID, vc)
	if err != nil {
		return "", fmt.Errorf("failed to save doc : %w", err)
	}

	return docID, nil
}

func (o *Operation) getComparatorConfig() (*compmodel.Config, error) {
	confResp, err := o.compClient.GetConfig(compclientops.NewGetConfigParams().
		WithTimeout(requestTimeout))
	if err != nil {
		return nil, fmt.Errorf("get config : %w", err)
	}

	if confResp.Payload == nil {
		return nil, errors.New("empty config from comparator")
	}

	return confResp.Payload, nil
}

func (o *Operation) getAuthorization(vaultID, rp, docID, authDID string) (string, error) {
	logger.Infof("getAuthorization : vaultID=[%s] rp=[%s] docID=[%s] authDID=[%s]", vaultID, rp, docID, authDID)

	docAuth, err := o.vClient.CreateAuthorization(
		vaultID,
		rp,
		&vault.AuthorizationsScope{
			Target:  docID,
			Actions: []string{"read"},
			Caveats: []vault.Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: uint64(authExpiryTime * time.Second)}},
		},
	)
	if err != nil {
		return "", fmt.Errorf("create vault authorization : %w", err)
	}

	if docAuth == nil || docAuth.Tokens == nil {
		return "", errors.New("missing auth token from vault-server")
	}

	logger.Infof("getAuthorization : edv=[%s] kms=[%s]", docAuth.Tokens.EDV, docAuth.Tokens.KMS)

	scope := &compmodel.Scope{
		Actions:     []string{"compare"},
		VaultID:     vaultID,
		DocID:       &docID,
		AuthTokens:  &compmodel.ScopeAuthTokens{Edv: docAuth.Tokens.EDV, Kms: docAuth.Tokens.KMS},
		DocAttrPath: nationalIDVCPath,
	}

	caveat := make([]compmodel.Caveat, 0)
	caveat = append(caveat, &compmodel.ExpiryCaveat{Duration: int64(authExpiryTime * time.Second)})

	scope.SetCaveats(caveat)

	authResp, err := o.compClient.PostAuthorizations(
		compclientops.NewPostAuthorizationsParams().
			WithTimeout(requestTimeout).
			WithAuthorization(
				&compmodel.Authorization{
					RequestingParty: &authDID,
					Scope:           scope,
				},
			),
	)
	if err != nil {
		return "", fmt.Errorf("create comparator authorization : %w", err)
	}

	if authResp == nil || authResp.Payload == nil {
		return "", errors.New("missing auth token from comparator")
	}

	logger.Infof("getAuthorization : token=[%s]", authResp.Payload.AuthToken)

	return authResp.Payload.AuthToken, nil
}

func (o *Operation) sendHTTPRequest(method, endpoint string, reqBody []byte, status int,
	httpToken string) ([]byte, error) {
	logger.Infof("sendHTTPRequest: method=[%s] url=[%s] reqBody=[%s]", method, endpoint, string(reqBody))

	req, err := http.NewRequest(method, endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	if httpToken != "" {
		req.Header.Add("Authorization", "Bearer "+httpToken)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
	}

	logger.Infof("httpResponse: status=[%d] respBody=[%s]", resp.StatusCode, string(respBody))

	if resp.StatusCode != status {
		return nil, fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

func getStore(prov storage.Provider, name string, config *storage.StoreConfiguration) (storage.Store, error) {
	txnStore, err := prov.OpenStore(name)
	if err != nil {
		return nil, err
	}

	if config != nil {
		err = prov.SetStoreConfig(name, *config)
		if err != nil {
			return nil, fmt.Errorf("failed to set store configuration for user-auth store: %w", err)
		}
	}

	return txnStore, nil
}

func clearCookies(w http.ResponseWriter) {
	cookie := http.Cookie{Name: actionCookie, Value: "", MaxAge: cookieExpiryTime, Path: "/"}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{Name: sessionidCookie, Value: "", MaxAge: cookieExpiryTime, Path: "/"}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{Name: idCookie, Value: "", MaxAge: cookieExpiryTime, Path: "/"}
	http.SetCookie(w, &cookie)
}

// nolint: interfacer
func resolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) error {
	for i := 1; i <= maxRetry; i++ {
		var err error
		_, err = vdrRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(1 * time.Second)

			continue
		}
	}

	return nil
}
