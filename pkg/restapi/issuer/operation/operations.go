/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/square/go-jose/jwt"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	edgesvcops "github.com/trustbloc/vcs/pkg/restapi/issuer/operation"
	vcprofile "github.com/trustbloc/vcs/pkg/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/trustbloc/sandbox/pkg/internal/common/support"
	oidcclient "github.com/trustbloc/sandbox/pkg/restapi/internal/common/oidc"
	"github.com/trustbloc/sandbox/pkg/token"
)

const (
	login                     = "/login"
	settings                  = "/settings"
	getCreditScore            = "/getCreditScore"
	callback                  = "/callback"
	generate                  = "/generate"
	revoke                    = "/revoke"
	didcommInit               = "/didcomm/init"
	didcommToken              = "/didcomm/token"
	didcommCallback           = "/didcomm/cb"
	didcommCredential         = "/didcomm/data"
	didcommAssuranceData      = "/didcomm/assurance"
	didcommUserEndpoint       = "/didcomm/uid"
	oauth2GetRequestPath      = "/oauth2/request"
	oauth2CallbackPath        = "/oauth2/callback"
	oauth2TokenRequestPath    = "oauth2/token" //nolint:gosec
	verifyDIDAuthPath         = "/verify/didauth"
	createCredentialPath      = "/credential"
	authPath                  = "/auth"
	preAuthorizePath          = "/pre-authorize"
	authCodeFlowPath          = "/auth-code-flow"
	openID4CIWebhookCheckPath = "/verify/openid4ci/webhook/check"
	openID4CIWebhookPath      = "/verify/openid4ci/webhook"
	searchPath                = "/search"
	generateCredentialPath    = createCredentialPath + "/generate"
	oidcRedirectPath          = "/oidc/redirect" + "/{id}"

	oidcIssuanceLogin            = "/oidc/login"
	oidcIssuerIssuance           = "/oidc/issuance"
	oidcIssuanceOpenID           = "/{id}/.well-known/openid-configuration"
	oidcIssuanceAuthorize        = "/{id}/oidc/authorize"
	oidcIssuanceAuthorizeRequest = "/oidc/authorize-request"
	//nolint: gosec
	oidcIssuanceToken      = "/{id}/oidc/token"
	oidcIssuanceCredential = "/{id}/oidc/credential"

	// http query params
	stateQueryParam = "state"

	credentialContext = "https://www.w3.org/2018/credentials/v1"

	vcsUpdateStatusURLFormat = "%s/%s" + "/credentials/status"

	vcsProfileCookie     = "vcsProfile"
	scopeCookie          = "scopeCookie"
	adapterProfileCookie = "adapterProfile"
	assuranceScopeCookie = "assuranceScope"
	callbackURLCookie    = "callbackURL"

	issueCredentialURLFormat = "%s/%s" + "/credentials/issue"

	// contexts
	trustBlocExampleContext = "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
	citizenshipContext      = "https://w3id.org/citizenship/v1"

	vcsIssuerRequestTokenName = "vcs_issuer"

	// store
	txnStoreName = "issuer_txn"

	scopeQueryParam         = "scope"
	externalScopeQueryParam = "subject_data"
)

// Mock signer for signing VCs.
const (
	pkBase58 = "2MP5gWCnf67jvW3E4Lz8PpVrDWAXMYY1sDxjnkEnKhkkbKD7yP2mkVeyVpu5nAtr3TeDgMNjBPirk2XcQacs3dvZ"
	kid      = "did:key:z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5#z6MknC1wwS6DEYwtGbZZo2QvjQjkh2qSBjb4GYmbye8dv4S5"
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
	handlers                 []Handler
	profiles                 []Profile
	tokenIssuer              tokenIssuer
	extTokenIssuer           tokenIssuer
	tokenResolver            tokenResolver
	documentLoader           ld.DocumentLoader
	cmsURL                   string
	vcsURL                   string
	walletURL                string
	receiveVCHTML            string
	didAuthHTML              string
	vcHTML                   string
	didCommHTML              string
	didCommVpHTML            string
	httpClient               *http.Client
	requestTokens            map[string]string
	issuerAdapterURL         string
	store                    storage.Store
	oidcClient               oidcClient
	externalDataSourceURL    string
	externalAuthClientID     string
	externalAuthClientSecret string
	externalAuthProviderURL  string
	homePage                 string
	didcommScopes            map[string]struct{}
	assuranceScopes          map[string]string
	tlsConfig                *tls.Config
	externalLogin            bool
	preAuthorizeHTML         string
	authCodeFlowHTML         string

	vcsAPIAccessTokenHost         string
	vcsAPIAccessTokenClientID     string
	vcsAPIAccessTokenClientSecret string
	vcsAPIAccessTokenClaim        string
	vcsAPIURL                     string
	vcsClaimDataURL               string
	vcsDemoIssuer                 string
	eventsTopic                   *EventsTopic
}

// Config defines configuration for issuer operations
type Config struct {
	Profiles                 []Profile
	TokenIssuer              tokenIssuer
	ExtTokenIssuer           tokenIssuer
	TokenResolver            tokenResolver
	DocumentLoader           ld.DocumentLoader
	CMSURL                   string
	VCSURL                   string
	WalletURL                string
	ReceiveVCHTML            string
	DIDAuthHTML              string
	VCHTML                   string
	PreAuthorizeHTML         string
	AuthCodeFlowHTML         string
	DIDCommHTML              string
	DIDCOMMVPHTML            string
	TLSConfig                *tls.Config
	RequestTokens            map[string]string
	IssuerAdapterURL         string
	StoreProvider            storage.Provider
	OIDCProviderURL          string
	OIDCClientID             string
	OIDCClientSecret         string
	OIDCCallbackURL          string
	ExternalDataSourceURL    string
	ExternalAuthProviderURL  string
	ExternalAuthClientID     string
	ExternalAuthClientSecret string
	didcommScopes            map[string]struct{}
	assuranceScopes          map[string]string
	externalLogin            bool

	VcsAPIAccessTokenHost         string
	VcsAPIAccessTokenClientID     string
	VcsAPIAccessTokenClientSecret string
	VcsAPIAccessTokenClaim        string
	VcsAPIURL                     string
	VcsClaimDataURL               string
	VcsDemoIssuer                 string
}

// vc struct used to return vc data to html
type vc struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

type initiate struct {
	URL         string        `json:"url"`
	TxID        string        `json:"txID"`
	SuccessText string        `json:"successText"`
	Pin         string        `json:"pin"`
	Profiles    []profileView `json:"profiles"`
}

type clientCredentialsTokenResponseStruct struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
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
func New(config *Config) (*Operation, error) { //nolint:funlen
	store, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, fmt.Errorf("issuer store provider : %w", err)
	}

	svc := &Operation{
		profiles:                      config.Profiles,
		tokenIssuer:                   config.TokenIssuer,
		extTokenIssuer:                config.ExtTokenIssuer,
		tokenResolver:                 config.TokenResolver,
		documentLoader:                config.DocumentLoader,
		cmsURL:                        config.CMSURL,
		vcsURL:                        config.VCSURL,
		walletURL:                     config.WalletURL,
		receiveVCHTML:                 config.ReceiveVCHTML,
		didAuthHTML:                   config.DIDAuthHTML,
		vcHTML:                        config.VCHTML,
		didCommHTML:                   config.DIDCommHTML,
		didCommVpHTML:                 config.DIDCOMMVPHTML,
		httpClient:                    &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:                 config.RequestTokens,
		issuerAdapterURL:              config.IssuerAdapterURL,
		store:                         store,
		externalDataSourceURL:         config.ExternalDataSourceURL,
		externalAuthClientID:          config.ExternalAuthClientID,
		externalAuthClientSecret:      config.ExternalAuthClientSecret,
		externalAuthProviderURL:       config.ExternalAuthProviderURL,
		homePage:                      config.OIDCCallbackURL,
		didcommScopes:                 map[string]struct{}{},
		assuranceScopes:               map[string]string{},
		tlsConfig:                     config.TLSConfig,
		externalLogin:                 config.externalLogin,
		preAuthorizeHTML:              config.PreAuthorizeHTML,
		authCodeFlowHTML:              config.AuthCodeFlowHTML,
		vcsAPIAccessTokenHost:         config.VcsAPIAccessTokenHost,
		vcsAPIAccessTokenClientID:     config.VcsAPIAccessTokenClientID,
		vcsAPIAccessTokenClientSecret: config.VcsAPIAccessTokenClientSecret,
		vcsAPIAccessTokenClaim:        config.VcsAPIAccessTokenClaim,
		vcsAPIURL:                     config.VcsAPIURL,
		vcsClaimDataURL:               config.VcsClaimDataURL,
		vcsDemoIssuer:                 config.VcsDemoIssuer,
		eventsTopic:                   NewEventsTopic(),
	}

	if config.didcommScopes != nil {
		svc.didcommScopes = config.didcommScopes
	}

	if config.assuranceScopes != nil {
		svc.assuranceScopes = config.assuranceScopes
	}

	if config.OIDCProviderURL != "" {
		svc.oidcClient, err = oidcclient.New(&oidcclient.Config{
			OIDCClientID:     config.OIDCClientID,
			OIDCClientSecret: config.OIDCClientSecret, OIDCCallbackURL: config.OIDCCallbackURL,
			OIDCProviderURL: config.OIDCProviderURL, TLSConfig: config.TLSConfig,
		})
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
		support.NewHTTPHandler(oidcRedirectPath, http.MethodGet, c.oidcRedirect),

		// issuer rest apis (html decoupled)
		support.NewHTTPHandler(authPath, http.MethodGet, c.auth),
		support.NewHTTPHandler(searchPath, http.MethodGet, c.search),
		support.NewHTTPHandler(verifyDIDAuthPath, http.MethodPost, c.verifyDIDAuthHandler),
		support.NewHTTPHandler(createCredentialPath, http.MethodPost, c.createCredentialHandler),
		support.NewHTTPHandler(generateCredentialPath, http.MethodPost, c.generateCredentialHandler),

		// chapi
		support.NewHTTPHandler(revoke, http.MethodPost, c.revokeVC),
		support.NewHTTPHandler(generate, http.MethodPost, c.generateVC),

		// oidc4ci authorize & pre-authorize
		support.NewHTTPHandler(preAuthorizePath, http.MethodGet, c.preAuthorize),
		support.NewHTTPHandler(authCodeFlowPath, http.MethodGet, c.authCodeFlowHandler),

		// webhooks
		support.NewHTTPHandler(openID4CIWebhookPath, http.MethodPost, c.eventsTopic.receiveTopics),
		support.NewHTTPHandler(openID4CIWebhookCheckPath, http.MethodGet, c.eventsTopic.checkTopics),

		// didcomm
		support.NewHTTPHandler(didcommToken, http.MethodPost, c.didcommTokenHandler),
		support.NewHTTPHandler(didcommCallback, http.MethodGet, c.didcommCallbackHandler),
		support.NewHTTPHandler(didcommCredential, http.MethodPost, c.didcommCredentialHandler),
		support.NewHTTPHandler(didcommAssuranceData, http.MethodPost, c.didcommAssuraceHandler),
		support.NewHTTPHandler(didcommInit, http.MethodGet, c.initiateDIDCommConnection),
		support.NewHTTPHandler(didcommUserEndpoint, http.MethodGet, c.getIDHandler),

		// oidc
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),

		// oidc issuance
		support.NewHTTPHandler(oidcIssuerIssuance, http.MethodPost, c.initiateIssuance),
		support.NewHTTPHandler(oidcIssuanceOpenID, http.MethodGet, c.wellKnownConfiguration),
		support.NewHTTPHandler(oidcIssuanceAuthorize, http.MethodGet, c.oidcAuthorize),
		support.NewHTTPHandler(oidcIssuanceAuthorizeRequest, http.MethodPost, c.oidcSendAuthorizeResponse),
		support.NewHTTPHandler(oidcIssuanceToken, http.MethodPost, c.oidcTokenEndpoint),
		support.NewHTTPHandler(oidcIssuanceCredential, http.MethodPost, c.oidcCredentialEndpoint),
	}
}

// login using oauth2, will redirect to Auth Code URL
func (c *Operation) login(w http.ResponseWriter, r *http.Request) {
	var u string

	scope := r.URL.Query()["scope"]
	extAuthURL := c.extTokenIssuer.AuthCodeURL(w)

	if len(scope) > 0 {
		// If the scope is PermanentResidentCard but external auth url is not defined
		// then proceed with trustbloc login service
		if scope[0] == externalScopeQueryParam && !strings.Contains(extAuthURL, "EXTERNAL") {
			c.externalLogin = true
			u = c.extTokenIssuer.AuthCodeURL(w)
			u += "&scope=" + oidc.ScopeOpenID + " " + scope[0]
		} else {
			u = c.prepareAuthCodeURL(w, scope[0])
		}
	}

	expire := time.Now().AddDate(0, 0, 1)

	if len(r.URL.Query()["vcsProfile"]) == 0 {
		logger.Errorf("vcs profile is empty")
		c.writeErrorResponse(w, http.StatusBadRequest, "vcs profile is empty")

		return
	}

	cookie := http.Cookie{Name: vcsProfileCookie, Value: r.URL.Query()["vcsProfile"][0], Expires: expire}
	http.SetCookie(w, &cookie)

	http.SetCookie(w, &http.Cookie{Name: callbackURLCookie, Value: "", Expires: expire})

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func (c *Operation) authCodeFlowHandler(w http.ResponseWriter, r *http.Request) {
	profile, err := c.determineProfile(r.URL.Query())
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	initiateReq := &initiateOIDC4CIRequest{
		CredentialTemplateID: profile.CredentialTemplateID,
		GrantType:            "authorization_code",
		ResponseType:         "code",
		Scope:                []string{"openid", "profile"},
		OpState:              uuid.New().String(),
		ClaimEndpoint:        c.vcsClaimDataURL,
	}

	c.buildInitiateOIDC4CIFlowPage(w, profile.ID, initiateReq, c.authCodeFlowHTML)
}

func (c *Operation) preAuthorize(w http.ResponseWriter, r *http.Request) {
	profile, err := c.determineProfile(r.URL.Query())
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	initiateReq := &initiateOIDC4CIRequest{
		CredentialTemplateID: profile.CredentialTemplateID,
		UserPinRequired:      true,
		ClaimData:            &profile.Claims,
	}

	if strings.EqualFold(r.URL.Query().Get("require_pin"), "false") {
		initiateReq.UserPinRequired = false
	}

	c.buildInitiateOIDC4CIFlowPage(w, profile.ID, initiateReq, c.preAuthorizeHTML)
}

func (c *Operation) buildInitiateOIDC4CIFlowPage( //nolint:funlen,gocyclo
	w http.ResponseWriter,
	profileID string,
	initiateReq *initiateOIDC4CIRequest,
	htmlTemplate string,
) {
	accessToken, err := c.issueAccessToken(
		c.vcsAPIAccessTokenHost,
		c.vcsAPIAccessTokenClientID,
		c.vcsAPIAccessTokenClientSecret,
		[]string{c.vcsAPIAccessTokenClaim},
	)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to get access token: %s", err.Error()))

		return
	}

	b, err := json.Marshal(initiateReq)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to marshal: %s", err.Error()))

		return
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%v/issuer/profiles/%v/interactions/initiate-oidc", c.vcsAPIURL, profileID),
		bytes.NewBuffer(b),
	)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("can not prepare http request: %s", err.Error()))

		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", accessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to send request for initiate: %s", err.Error()))

		return
	}

	if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close() //nolint:errcheck
		}()
	}

	var parsedResp initiateOIDC4CIResponse

	if err = json.NewDecoder(resp.Body).Decode(&parsedResp); err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to decode initiate response: %s", err.Error()))

		return
	}

	pin := ""
	if parsedResp.UserPin != nil {
		pin = *parsedResp.UserPin
	}

	var successText strings.Builder
	successText.WriteString(fmt.Sprintf("Credentials with template [%v] and type [%v] ",
		initiateReq.CredentialTemplateID, "VerifiedEmployee"))

	if initiateReq.ClaimData != nil {
		successText.WriteString("and claims: ")
		for k, v := range *initiateReq.ClaimData {
			successText.WriteString(fmt.Sprintf("%v:%v ", k, v))
		}
	}
	successText.WriteString(fmt.Sprintf("was successfully issued by [%v]", c.vcsAPIAccessTokenClientID))

	t, err := template.ParseFiles(htmlTemplate)
	if err != nil {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	if err = t.Execute(w, initiate{
		URL:         parsedResp.OfferCredentialURL,
		TxID:        parsedResp.TxID,
		SuccessText: successText.String(),
		Pin:         pin,
		Profiles:    c.buildProfileList(profileID),
	}); err != nil {
		logger.Errorf(fmt.Sprintf("execute html template: %s", err.Error()))
	}
}

func (c *Operation) buildProfileList(currentProfile string) []profileView {
	var profileList []profileView

	for _, p := range c.profiles {
		profileList = append(profileList,
			profileView{
				ID:         p.ID,
				Name:       p.Name,
				IsSelected: p.ID == currentProfile,
			},
		)
	}

	return profileList
}

func (c *Operation) determineProfile(query url.Values) (*Profile, error) {
	var profile *Profile

	profileID := getProfileID(query)

	if profileID != "" {
		profile = c.getProfile(profileID)
		if profile == nil {
			return nil, fmt.Errorf("profile %s was not found", profileID)
		}
	} else {
		profile = c.getDefaultProfile()
	}

	return profile, nil
}

func (c *Operation) getProfile(profileID string) *Profile {
	for _, p := range c.profiles {
		if p.ID == profileID {
			return &p
		}
	}

	return nil
}

func (c *Operation) getDefaultProfile() *Profile {
	return &c.profiles[0]
}

func getProfileID(query url.Values) string {
	return query.Get("profile_id")
}

func (c *Operation) issueAccessToken(oidcProviderURL, clientID, secret string, scopes []string) (string, error) {
	conf := clientcredentials.Config{
		TokenURL:     oidcProviderURL + "/oauth2/token",
		ClientID:     clientID,
		ClientSecret: secret,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, c.httpClient)

	tokenResult, err := conf.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return tokenResult.AccessToken, nil
}

func (c *Operation) auth(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query()["scope"]
	if len(scope) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest, "scope is mandatory")

		return
	}

	callBackURL := r.URL.Query()["callbackURL"]

	if len(callBackURL) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest, "callbackURL is mandatory")

		return
	}

	referrer := r.URL.Query()["referrer"]

	if len(referrer) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest, "referrer is mandatory")

		return
	}

	u := c.tokenIssuer.AuthCodeURL(w)
	u += "&scope=" + scope[0]

	cookie := http.Cookie{
		Name:    callbackURLCookie,
		Value:   callBackURL[0],
		Expires: time.Now().AddDate(0, 0, 1),
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/oidc/redirect/"+referrer[0]+"?url="+url.QueryEscape(u), http.StatusTemporaryRedirect)
}

func (c *Operation) oidcRedirect(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query()["url"]
	if len(u) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest, "url is mandatory")

		return
	}

	const redirectHTML = `
	<!DOCTYPE html>
	<html>
	<head>
	  <meta name="referrer" content="no-referrer-when-downgrade"/>
	  <meta http-equiv="refresh" content="0; url='%s'" />
	</head>
	</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, redirectHTML, u[0])
}

func (c *Operation) search(w http.ResponseWriter, r *http.Request) {
	txnID := r.URL.Query()["txnID"]
	if len(txnID) == 0 {
		c.writeErrorResponse(w, http.StatusBadRequest, "txnID is mandatory")

		return
	}

	dataBytes, err := c.store.Get(txnID[0])
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get txn data: %s", err.Error()))

		return
	}

	logger.Infof("preview : sessionData=%s", string(dataBytes))

	var data *txnData

	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("unmarshal session data: %s", err.Error()))

		return
	}

	// TODO enhance the api to support dynamic search
	userData, err := c.getCMSUserData(strings.ToLower(data.Scope)+"s", data.UserID, data.Token)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get user data : %s", err.Error()))

		return
	}

	userDatabytes, err := json.Marshal(&searchData{
		Scope:    data.Scope,
		UserData: userData,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal user data : %s", err.Error()))

		return
	}

	keyID := uuid.NewString()

	err = c.store.Put(keyID, userDatabytes)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get assurance data : %s", err.Error()))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(fmt.Sprintf(`{"id" : "%s"}`, keyID)))
}

// initiateDIDCommConnection initiates a DIDComm connection from the issuer to the user's wallet
func (c *Operation) initiateDIDCommConnection(w http.ResponseWriter, r *http.Request) {
	issuerID := r.FormValue("adapterProfile")
	if issuerID == "" {
		logger.Errorf("missing adapterProfile")
		c.writeErrorResponse(w, http.StatusBadRequest, "missing adapterProfile")

		return
	}

	scope := r.FormValue("didCommScope")
	if scope == "" {
		logger.Errorf("missing didCommScope")
		c.writeErrorResponse(w, http.StatusBadRequest, "missing didCommScope")

		return
	}

	assuranceScope := r.FormValue("assuranceScope")

	c.didcommScopes[scope] = struct{}{}

	if assuranceScope != "" {
		c.assuranceScopes[scope] = assuranceScope
	}

	rURL := fmt.Sprintf("%s/%s/connect/wallet?cred=%s", c.issuerAdapterURL, issuerID, scope)
	http.Redirect(w, r, rURL, http.StatusFound)
}

func (c *Operation) hasAccessToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ")
}

func (c *Operation) getTokenInfo(w http.ResponseWriter, r *http.Request) (*token.Introspection, *oauth2.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		logger.Infof("rejected request lacking Bearer token")
		w.Header().Add("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)

		return nil, nil, fmt.Errorf("missing bearer token")
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	tk := oauth2.Token{AccessToken: accessToken}

	info, err := c.tokenResolver.Resolve(accessToken)
	if err != nil {
		logger.Errorf("failed to get token info: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get token info: %s", err.Error()))

		return nil, nil, fmt.Errorf("\"failed to get token info: %w", err)
	}

	if !info.Active {
		logger.Infof("rejected request with invalid token")
		c.writeErrorResponse(w, http.StatusUnauthorized, `Bearer error="invalid_token"`)

		return nil, nil, fmt.Errorf("token is invalid")
	}

	return info, &tk, nil
}

func (c *Operation) getIDHandler(w http.ResponseWriter, r *http.Request) {
	info, tk, err := c.getTokenInfo(w, r)
	if err != nil {
		return
	}

	user, err := c.getCMSUser(tk, "email="+info.Subject)
	if err != nil {
		logger.Errorf("failed to get cms user: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get cms user: %s", err.Error()))

		return
	}

	resp := adapterTokenResp{
		UserID: user.UserID,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal userID response : %s", err.Error()))
		return
	}

	c.writeResponse(w, http.StatusOK, respBytes)
}

func (c *Operation) getDIDCommScopes(scopes string) []string {
	var out []string

	for _, scope := range strings.Split(scopes, " ") {
		if _, ok := c.didcommScopes[scope]; ok {
			out = append(out, scope)
		}
	}

	return out
}

// getCredentialUsingAccessToken services offline credential requests using an Oauth2 Bearer access token
func (c *Operation) getCredentialUsingAccessToken(w http.ResponseWriter, r *http.Request) {
	info, tk, err := c.getTokenInfo(w, r)
	if err != nil {
		return
	}

	scopes := strings.Join(c.getDIDCommScopes(info.Scope), " ")
	if scopes == "" {
		logger.Errorf("no valid credential scope")
		c.writeErrorResponse(w, http.StatusInternalServerError, "no valid credential scope")

		return
	}

	_, subjectData, err := c.getCMSData(tk, "email="+info.Subject, scopes)
	if err != nil {
		logger.Errorf("failed to get cms data: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	delete(subjectData, "vcmetadata")
	delete(subjectData, "vccredentialsubject")

	subjectDataBytes, err := json.Marshal(subjectData)
	if err != nil {
		logger.Errorf("failed to marshal subject data: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal subject data: %s", err.Error()))

		return
	}

	c.writeResponse(w, http.StatusOK, subjectDataBytes)
}

// getAssuranceUsingAccessToken services offline assurance requests using an Oauth2 Bearer access token
func (c *Operation) getAssuranceUsingAccessToken(w http.ResponseWriter, r *http.Request) {
	info, tk, err := c.getTokenInfo(w, r)
	if err != nil {
		return
	}

	user, err := c.getCMSUser(tk, "email="+info.Subject)
	if err != nil {
		logger.Errorf("failed to get cms user: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get cms user: %s", err.Error()))

		return
	}

	scopes := c.getDIDCommScopes(info.Scope)

	assuranceScope := ""

	for _, scope := range scopes {
		if s, ok := c.assuranceScopes[scope]; ok {
			assuranceScope = s
			break
		}
	}

	if assuranceScope == "" {
		logger.Errorf("no assurance scope for credential scopes %v", scopes)
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("no assurance scope for credential scopes %v", scopes))

		return
	}

	assuranceData, err := c.getCMSUserData(assuranceScope, user.UserID, "")
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

	c.writeResponse(w, http.StatusOK, dataBytes)
}

func (c *Operation) settings(w http.ResponseWriter, r *http.Request) {
	u := c.homePage

	expire := time.Now().AddDate(0, 0, 1)

	if len(r.URL.Query()["vcsProfile"]) == 0 {
		logger.Errorf("vcs profile is empty")
		c.writeErrorResponse(w, http.StatusBadRequest, "vcs profile is empty")

		return
	}

	cookie := http.Cookie{Name: vcsProfileCookie, Value: r.URL.Query()["vcsProfile"][0], Expires: expire}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// callback for oauth2 login
func (c *Operation) callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()["error"]) != 0 {
		if r.URL.Query()["error"][0] == "access_denied" {
			http.Redirect(w, r, c.homePage, http.StatusTemporaryRedirect)
		}
	}

	vcsProfileCookie, err := r.Cookie(vcsProfileCookie)
	if err != nil {
		logger.Errorf("failed to get cookie: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cookie: %s", err.Error()))

		return
	}

	if c.externalLogin {
		c.getDataFromExternalSource(w, r, externalScopeQueryParam, vcsProfileCookie.Value)
	} else {
		c.getDataFromCms(w, r, vcsProfileCookie.Value)
	}
}

func (c *Operation) getDataFromExternalSource(w http.ResponseWriter, r *http.Request, scope, //nolint: funlen
	vcsCookie string,
) {
	tk, err := c.extTokenIssuer.Exchange(r)
	if err != nil {
		logger.Errorf("failed to exchange code for token: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to exchange code for token: %s", err.Error()))

		return
	}
	// Fetching idToken from the token issuer
	idToken, ok := tk.Extra("id_token").(string)
	if !ok {
		logger.Errorf("failed to get id token: %s", err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get id token: %s", err.Error()))

		return
	}

	subRefClaim, err := getSubjectReferenceClaim(idToken)
	if err != nil {
		logger.Errorf("failed to get subject reference claim: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get subject reference claim: %s", err.Error()))

		return
	}

	// get the access_token
	accessToken, err := c.getAccessToken(externalScopeQueryParam)
	if err != nil {
		logger.Errorf("failed to get access token: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get access token: %s", err.Error()))

		return
	}

	// get subject data from internal data source
	subjectData, err := c.getSubjectData(accessToken, subRefClaim)
	if err != nil {
		logger.Errorf("failed to get subject data from internal data source: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get subject data from internal data source: %s", err.Error()))

		return
	}

	// get the subject data and prepare credential
	cred, err := c.prepareCredential(subjectData, scope, vcsCookie)
	if err != nil {
		logger.Errorf("failed to create credential now: %s", err.Error())
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
		"Path": generate + "?" + "profile=" + vcsCookie,
		"Cred": string(cred),
	}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

func (c *Operation) getDataFromCms(w http.ResponseWriter, r *http.Request, vcsCookie string) { //nolint: funlen,gocyclo
	tk, e := c.tokenIssuer.Exchange(r)
	if e != nil {
		logger.Errorf("failed to exchange code for token while getting data from cms : %s ", e.Error())
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to exchange code for token while getting data from cms : %s", e.Error()))

		return
	}
	// user info from token will be used for to retrieve data from cms
	info, err := c.tokenResolver.Resolve(tk.AccessToken)
	if err != nil {
		logger.Errorf("failed to get token info: %s and access token %s", err.Error(), tk.AccessToken)
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get token info: %s and access token %s", err.Error(), tk.AccessToken))

		return
	}

	userID, subject, err := c.getCMSData(tk, "email="+info.Subject, info.Scope)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get cms data: %s", err.Error()))

		return
	}

	callbackURLCookie, err := r.Cookie(callbackURLCookie)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get authMode cookie: %s", err.Error()))

		return
	}

	if callbackURLCookie != nil && callbackURLCookie.Value != "" {
		txnID := uuid.NewString()
		data := txnData{
			UserID: userID,
			Scope:  info.Scope,
			Token:  tk.AccessToken,
		}

		dataBytes, mErr := json.Marshal(data)
		if mErr != nil {
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to marshal txn data: %s", mErr.Error()))
			return
		}

		err = c.store.Put(txnID, dataBytes)
		if err != nil {
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to save txn data: %s", err.Error()))

			return
		}

		http.Redirect(w, r, callbackURLCookie.Value+"?txnID="+txnID, http.StatusTemporaryRedirect)

		return
	}

	cred, err := c.prepareCredential(subject, info.Scope, vcsCookie)
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
		"Path": generate + "?" + "profile=" + vcsCookie,
		"Cred": string(cred),
	}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute qr html template: %s", err.Error()))
	}
}

func (c *Operation) getAccessToken(scope string) (string, error) {
	// call auth api to get access token
	req := url.Values{}
	req.Set("client_id", c.externalAuthClientID)
	req.Set("grant_type", "client_credentials")
	req.Set("scope", scope)
	reqBodyBytes := bytes.NewBuffer([]byte(req.Encode()))

	httpRequest, err := http.NewRequest("POST", c.externalAuthProviderURL+oauth2TokenRequestPath, reqBodyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to post the request %w", err)
	}

	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.SetBasicAuth(url.QueryEscape(c.externalAuthClientID), url.QueryEscape(c.externalAuthClientSecret))

	resp, err := sendHTTPRequest(httpRequest, c.httpClient, http.StatusOK, "")
	if err != nil {
		return "", fmt.Errorf("failed to post the request to get the access token %w", err)
	}

	// unmarshal the response
	var tokenResponse clientCredentialsTokenResponseStruct

	err = json.Unmarshal(resp, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling the token response %w", err)
	}

	return tokenResponse.AccessToken, nil
}

func (c *Operation) getSubjectData(accessToken, subRefClaim string) (subjectData map[string]interface{}, err error) {
	// pass access token to subjects/data?
	req, err := http.NewRequest("GET", c.externalDataSourceURL+"1.0/subjects/data?", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject data %w", err)
	}

	reqQuery := req.URL.Query()
	reqQuery.Add("aiid", "FiIJethCqaTkWh70Gq8D")
	reqQuery.Add("subjectReference", subRefClaim)
	req.URL.RawQuery = reqQuery.Encode()

	resp, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to get the subject data %w", err)
	}

	err = json.Unmarshal(resp, &subjectData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling the subject data  %w", err)
	}

	return subjectData, nil
}

func getSubjectReferenceClaim(idToken string) (string, error) {
	var claims jwt.Claims

	jwtToken, err := jwt.ParseSigned(idToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse id token %w", err)
	}

	err = jwtToken.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", fmt.Errorf("failed to deserializes the claims of jwt %w", err)
	}

	return claims.Subject, nil
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

func (c *Operation) verifyDIDAuthHandler(w http.ResponseWriter, r *http.Request) {
	req := &verifyDIDAuthReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	err = c.validateAuthResp(req.DIDAuthResp, req.Holder, req.Domain, req.Challenge)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to validate did auth resp : %s", err.Error()))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(""))
}

func (c *Operation) createCredentialHandler(w http.ResponseWriter, r *http.Request) {
	req := &createCredentialReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	// get data from cms
	userData, err := c.getCMSUserData(req.Collection, req.UserID, "")
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to get cms user data : %s", err.Error()))

		return
	}

	// support for dynamically adding subject data
	if len(req.CustomSubjectData) > 0 {
		if s, ok := userData["vccredentialsubject"]; ok && len(req.CustomSubjectData) > 0 {
			if subject, ok := s.(map[string]interface{}); ok {
				for k, v := range req.CustomSubjectData {
					subject[k] = v
				}
			}
		} else {
			userData["vccredentialsubject"] = req.CustomSubjectData
		}
	}

	// create credential
	cred, err := c.prepareCredential(userData, req.Scope, req.VCSProfile)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	signedVC, err := c.issueCredential(req.VCSProfile, req.Holder, cred)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to sign credential: %s", err.Error()))

		return
	}

	c.writeResponse(w, http.StatusOK, signedVC)
}

func (c *Operation) generateCredentialHandler(w http.ResponseWriter, r *http.Request) {
	req := &generateCredentialReq{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	dataBytes, err := c.store.Get(req.ID)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to get user data using id '%s' : %s", req.ID, err.Error()))

		return
	}

	var sData *searchData

	err = json.Unmarshal(dataBytes, &sData)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to unmarshal user data : %s", err.Error()))

		return
	}

	// create credential
	cred, err := c.prepareCredential(sData.UserData, sData.Scope, req.VCSProfile)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	signedVC, err := c.issueCredential(req.VCSProfile, req.Holder, cred)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to sign credential: %s", err.Error()))

		return
	}

	c.writeResponse(w, http.StatusOK, signedVC)
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
	if errors.Is(err, storage.ErrDataNotFound) {
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
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		logger.Errorf("failed to parse presentation: %s", err.Error())
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse presentation: %s", err.Error()))

		return
	}

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

		vc, errParse := verifiable.ParseCredential(credBytes, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.documentLoader))
		if errParse != nil {
			logger.Errorf("failed to parse credentials: %s", errParse.Error())
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to parse credentials: %s", errParse.Error()))

			return
		}

		reqBytes, errPrepare := prepareUpdateCredentialStatusRequest(vc)
		if errPrepare != nil {
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to prepare update credential status request: %s", errPrepare.Error()))

			return
		}

		endpointURL := fmt.Sprintf(vcsUpdateStatusURLFormat, c.vcsURL, vc.Issuer.CustomFields["name"].(string))

		req, errReq := http.NewRequest("POST", endpointURL,
			bytes.NewBuffer(reqBytes))
		if errReq != nil {
			logger.Errorf("failed to create new http request: %s", errReq.Error())
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to create new http request: %s", errReq.Error()))

			return
		}

		_, err = sendHTTPRequest(req, c.httpClient, http.StatusOK, c.requestTokens[vcsIssuerRequestTokenName])
		if err != nil {
			logger.Errorf("failed to update vc status: %s", err.Error())
			c.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("failed to update vc status: %s", err.Error()))

			return
		}
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

func (c *Operation) initiateIssuance(w http.ResponseWriter, r *http.Request) {
	oidcIssuanceReq := &oidcIssuanceRequest{}

	err := json.NewDecoder(r.Body).Decode(oidcIssuanceReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	walletURL := oidcIssuanceReq.WalletInitIssuanceURL
	if walletURL == "" {
		walletURL = c.walletURL
	}

	credentialTypes := strings.Split(oidcIssuanceReq.CredentialTypes, ",")
	manifestIDs := strings.Split(oidcIssuanceReq.ManifestIDs, ",")
	issuerURL := oidcIssuanceReq.IssuerURL
	credManifest := oidcIssuanceReq.CredManifest
	credential := oidcIssuanceReq.Credential

	key := uuid.NewString()
	issuer := issuerURL + "/" + key

	issuerConf, err := json.MarshalIndent(&issuerConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oidc/authorize",
		TokenEndpoint:         issuer + "/oidc/token",
		CredentialEndpoint:    issuer + "/oidc/credential",
		CredentialManifests:   credManifest,
	}, "", "	")
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to prepare issuer wellknown configuration : %s", err))

		return
	}

	err = c.saveIssuanceConfig(key, issuerConf, credential)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to store issuer server configuration : %s", err))

		return
	}

	redirectURL, err := parseWalletURL(walletURL, issuer, credentialTypes, manifestIDs)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse wallet init issuance URL : %s", err))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(redirectURL))
}

func parseWalletURL(walletURL, issuer string, credentialTypes, manifestIDs []string) (string, error) {
	u, err := url.Parse(walletURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse wallet init issuance URL : %w", err)
	}

	q := u.Query()
	q.Set("issuer", issuer)

	for _, credType := range credentialTypes {
		q.Add("credential_type", credType)
	}

	for _, manifestID := range manifestIDs {
		q.Add("manifest_id", manifestID)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func (c *Operation) saveIssuanceConfig(key string, issuerConf, credential []byte) error {
	err := c.store.Put(key, issuerConf)
	if err != nil {
		return fmt.Errorf("failed to store issuer server configuration : %w", err)
	}

	err = c.store.Put(getCredStoreKeyPrefix(key), credential)
	if err != nil {
		return fmt.Errorf("failed to store credential : %w", err)
	}

	return nil
}

func (c *Operation) wellKnownConfiguration(w http.ResponseWriter, r *http.Request) {
	enableCors(w)

	id := mux.Vars(r)["id"]

	issuerConf, err := c.store.Get(id)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to read well known configuration : %s", err))

		return
	}

	w.Header().Set("Content-Type", "application/json")
	c.writeResponse(w, http.StatusOK, issuerConf)
}

func (c *Operation) oidcAuthorize(w http.ResponseWriter, r *http.Request) { //nolint: funlen
	if err := r.ParseForm(); err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to parse request : %s", err))

		return
	}

	claims, err := url.PathUnescape(r.Form.Get("claims"))
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to read claims : %s", err))

		return
	}

	redirectURI, err := url.PathUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to read redirect URI : %s", err))

		return
	}

	scope := r.Form.Get("scope")
	state := r.Form.Get("state")
	responseType := r.Form.Get("response_type")
	clientID := r.Form.Get("client_id")

	// basic validation only.
	if claims == "" || redirectURI == "" || clientID == "" || state == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "Invalid Request")

		return
	}

	authState := uuid.NewString()

	authRequest, err := json.Marshal(map[string]string{
		"claims":        claims,
		"scope":         scope,
		"state":         state,
		"response_type": responseType,
		"client_id":     clientID,
		"redirect_uri":  redirectURI,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to process authorization request : %s", err))

		return
	}

	err = c.store.Put(getAuthStateKeyPrefix(authState), authRequest)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to save state : %s", err))

		return
	}

	authStateCookie := http.Cookie{
		Name:    "state",
		Value:   authState,
		Expires: time.Now().Add(5 * time.Minute), //nolint: gomnd
		Path:    "/",
	}

	http.SetCookie(w, &authStateCookie)
	http.Redirect(w, r, oidcIssuanceLogin, http.StatusFound)
}

func (c *Operation) oidcSendAuthorizeResponse(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("state")
	if err != nil {
		c.writeErrorResponse(w, http.StatusForbidden, "invalid state")

		return
	}

	authRqstBytes, err := c.store.Get(getAuthStateKeyPrefix(stateCookie.Value))
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, "invalid request")

		return
	}

	var authRequest map[string]string

	err = json.Unmarshal(authRqstBytes, &authRequest)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "failed to read request")

		return
	}

	redirectURI, ok := authRequest["redirect_uri"]
	if !ok {
		c.writeErrorResponse(w, http.StatusInternalServerError, "failed to redirect, invalid URL")

		return
	}

	state, ok := authRequest["state"]
	if !ok {
		c.writeErrorResponse(w, http.StatusInternalServerError, "failed to redirect, invalid state")

		return
	}

	authCode := uuid.NewString()

	err = c.store.Put(getAuthCodeKeyPrefix(authCode), []byte(stateCookie.Value))
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "failed to store state cookie value")

		return
	}

	redirectTo := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)

	// TODO process credential types or manifests from claims and prepare credential
	// endpoint with credential to be issued.
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (c *Operation) oidcTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	setOIDCResponseHeaders(w)

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	grantType := r.FormValue("grant_type")

	if grantType != "authorization_code" {
		c.sendOIDCErrorResponse(w, "unsupported grant type", http.StatusBadRequest)
		return
	}

	authState, err := c.store.Get(getAuthCodeKeyPrefix(code))
	if err != nil {
		c.sendOIDCErrorResponse(w, "invalid state", http.StatusBadRequest)
		return
	}

	authRqstBytes, err := c.store.Get(getAuthStateKeyPrefix(string(authState)))
	if err != nil {
		c.sendOIDCErrorResponse(w, "invalid request", http.StatusBadRequest)
		return
	}

	var authRequest map[string]string

	err = json.Unmarshal(authRqstBytes, &authRequest)
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to read request", http.StatusInternalServerError)
		return
	}

	if authRedirectURI := authRequest["redirect_uri"]; authRedirectURI != redirectURI {
		c.sendOIDCErrorResponse(w, "request validation failed", http.StatusInternalServerError)
		return
	}

	mockAccessToken := uuid.NewString()
	mockIssuerID := mux.Vars(r)["id"]

	err = c.store.Put(getAccessTokenKeyPrefix(mockAccessToken), []byte(mockIssuerID))
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to save token state", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]interface{}{
		"token_type":   "Bearer",
		"access_token": mockAccessToken,
		"expires_in":   3600 * time.Second, //nolint: gomnd
	})
	// TODO add id_token, c_nonce, c_nonce_expires_in
	if err != nil {
		c.sendOIDCErrorResponse(w, "response_write_error", http.StatusBadRequest)

		return
	}

	c.writeResponse(w, http.StatusOK, response)
}

func (c *Operation) oidcCredentialEndpoint(w http.ResponseWriter, r *http.Request) { //nolint: funlen,gocyclo
	setOIDCResponseHeaders(w)

	// TODO read and validate credential 'type', useful in multiple credential download.
	format := r.FormValue("format")

	if format != "" && format != "ldp_vc" {
		c.sendOIDCErrorResponse(w, "unsupported format requested", http.StatusBadRequest)
		return
	}

	authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	if len(authHeader) != 2 { //nolint: gomnd
		c.sendOIDCErrorResponse(w, "malformed token", http.StatusBadRequest)
		return
	}

	if authHeader[1] == "" {
		c.sendOIDCErrorResponse(w, "invalid token", http.StatusForbidden)
		return
	}

	mockIssuerID := mux.Vars(r)["id"]

	issuerID, err := c.store.Get(getAccessTokenKeyPrefix(authHeader[1]))
	if err != nil {
		c.sendOIDCErrorResponse(w, "unsupported format requested", http.StatusBadRequest)
		return
	}

	if mockIssuerID != string(issuerID) {
		c.sendOIDCErrorResponse(w, "invalid transaction", http.StatusForbidden)
		return
	}

	credentialBytes, err := c.store.Get(getCredStoreKeyPrefix(mockIssuerID))
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to get credential", http.StatusInternalServerError)
		return
	}

	docLoader := ld.NewDefaultDocumentLoader(nil)

	credential, err := verifiable.ParseCredential(credentialBytes, verifiable.WithJSONLDDocumentLoader(docLoader))
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to prepare credential", http.StatusInternalServerError)
		return
	}

	err = signVCWithED25519(credential, docLoader)
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to issue credential", http.StatusInternalServerError)
		return
	}

	credBytes, err := credential.MarshalJSON()
	if err != nil {
		c.sendOIDCErrorResponse(w, "failed to write credential bytes", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(map[string]interface{}{
		"format":     format,
		"credential": json.RawMessage(credBytes),
	})
	// TODO add support for acceptance token & nonce for deferred flow.
	if err != nil {
		c.sendOIDCErrorResponse(w, "response_write_error", http.StatusBadRequest)
		return
	}

	c.writeResponse(w, http.StatusOK, response)
}

func setOIDCResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (c *Operation) sendOIDCErrorResponse(w http.ResponseWriter, msg string, status int) {
	w.WriteHeader(status)
	c.writeResponse(w, status, []byte(fmt.Sprintf(`{"error": "%s"}`, msg)))
}

func enableCors(w http.ResponseWriter) {
	(w).Header().Set("Access-Control-Allow-Origin", "*")
}

// didcomm redirects to the issuer-adapter so it connects to the wallet over DIDComm.
func (c *Operation) didcomm(w http.ResponseWriter, r *http.Request, userID string, subjectData map[string]interface{},
	issuerID string,
) {
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
		logger.Errorf("failed execute didcomm html template: %s", err.Error())
	} else {
		logger.Infof("didcomm callback handler success")
	}
}

func (c *Operation) didcommCredentialHandler(w http.ResponseWriter, r *http.Request) {
	if c.hasAccessToken(r) {
		c.getCredentialUsingAccessToken(w, r)
		return
	}

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
	if c.hasAccessToken(r) {
		c.getAssuranceUsingAccessToken(w, r)
		return
	}

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

	assuranceData, err := c.getCMSUserData(userData.AssuranceScope, userData.ID, "")
	if err != nil {
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

func (c *Operation) getCMSUserData(scope, userID, tkn string) (map[string]interface{}, error) {
	u := c.cmsURL + "/" + scope + "?userid=" + userID

	logger.Infof("url = %s", u)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	subjectBytes, err := sendHTTPRequest(req, c.httpClient, http.StatusOK, tkn)
	if err != nil {
		return nil, err
	}

	return unmarshalSubject(subjectBytes)
}

func (c *Operation) validateAdapterCallback(redirectURL string) error {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return fmt.Errorf("didcomm callback - error parsing the request url: %w", err)
	}

	state := u.Query().Get(stateQueryParam)
	if state == "" {
		return errors.New("missing state in http query param")
	}

	_, err = c.store.Get(state)
	if err != nil {
		return fmt.Errorf("invalid state : %w", err)
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

func (c *Operation) prepareCredential(subject map[string]interface{}, scope, vcsProfile string) ([]byte, error) {
	// will be replaced by DID auth response subject ID
	subject["id"] = ""
	defaultCredTypes := []string{"VerifiableCredential", "PermanentResidentCard"}
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
		return nil, fmt.Errorf("retrieve profile - name=%s err=%w", vcsProfile, err)
	}

	cred := &verifiable.Credential{}
	// Todo ideally scope should be what need to passed as a type
	// but from external data source the scope is subject_data. Need to revisit this logic
	switch scope {
	case externalScopeQueryParam:
		cred.Types = defaultCredTypes
		cred.Subject = subject["subjectData"]
		customFields["name"] = "Permanent Resident Card"
		cred.Context = []string{credentialContext, citizenshipContext}
	default:
		cred.Types = []string{"VerifiableCredential", scope}
		cred.Context = vcContext
		cred.Subject = subject
	}

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

	return c.issueCredential(id, holder, []byte(cred))
}

func (c *Operation) issueCredential(profileID, holder string, cred []byte) ([]byte, error) {
	credential, err := verifiable.ParseCredential(cred, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %w", err)
	}

	if subject, ok := credential.Subject.([]verifiable.Subject); ok && len(subject) > 0 {
		subject[0].ID = holder
	} else if subjectString, ok := credential.Subject.(string); ok {
		subject := make([]verifiable.Subject, 1)

		subject[0].ID = subjectString
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

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, c.vcsURL, profileID)

	req, err := http.NewRequest("POST", endpointURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	return sendHTTPRequest(req, c.httpClient, http.StatusCreated, c.requestTokens[vcsIssuerRequestTokenName])
}

// validateAuthResp validates did auth response against given domain and challenge
func (c *Operation) validateAuthResp(authResp []byte, holder, domain, challenge string) error { // nolint:gocyclo
	vp, err := verifiable.ParsePresentation(authResp, verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return err
	}

	if vp.Holder != holder {
		return fmt.Errorf("invalid auth response, invalid holder proof")
	}

	proofOfInterest := vp.Proofs[0]

	var proofChallenge, proofDomain string

	{
		d, ok := proofOfInterest["challenge"]
		if ok && d != nil {
			proofChallenge, ok = d.(string)
		}

		if !ok {
			return fmt.Errorf("invalid auth response proof, missing challenge")
		}
	}

	{
		d, ok := proofOfInterest["domain"]
		if ok && d != nil {
			proofDomain, ok = d.(string)
		}

		if !ok {
			return fmt.Errorf("invalid auth response proof, missing domain")
		}
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

func prepareUpdateCredentialStatusRequest(vc *verifiable.Credential) ([]byte, error) {
	request := edgesvcops.UpdateCredentialStatusRequest{
		CredentialID:     vc.ID,
		CredentialStatus: edgesvcops.CredentialStatus{Type: csl.StatusList2021Entry, Status: "1"},
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

func signVCWithED25519(vc *verifiable.Credential, loader ld.DocumentLoader) error {
	edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))
	edSigner := &edd25519Signer{edPriv}
	sigSuite := ed25519signature2018.New(suite.WithSigner(edSigner))

	tt := time.Now()

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      kid,
		Purpose:                 "assertionMethod",
		Created:                 &tt,
	}

	return vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(loader))
}

// nolint:interfacer
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("failed to read response body for status: %d", resp.StatusCode)
		}

		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
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
	logger.Errorf(msg)

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

func getCredStoreKeyPrefix(key string) string {
	return fmt.Sprintf("cred_store_%s", key)
}

func getAuthStateKeyPrefix(key string) string {
	return fmt.Sprintf("authstate_%s", key)
}

func getAuthCodeKeyPrefix(key string) string {
	return fmt.Sprintf("authcode_%s", key)
}

func getAccessTokenKeyPrefix(key string) string {
	return fmt.Sprintf("access_token_%s", key)
}

// signer for signing ed25519 for tests.
type edd25519Signer struct {
	privateKey []byte
}

func (s *edd25519Signer) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func (s *edd25519Signer) Alg() string {
	return ""
}

func (c *Operation) prepareAuthCodeURL(w http.ResponseWriter, scope string) string {
	u := c.tokenIssuer.AuthCodeURL(w)
	if scope == externalScopeQueryParam {
		u += "&scope=" + "PermanentResidentCard"
	} else {
		u += "&scope=" + scope
	}

	return u
}
