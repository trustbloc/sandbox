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
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/square/go-jose/jwt"
	"github.com/trustbloc/edge-core/pkg/log"
	edgesvcops "github.com/trustbloc/vcs/pkg/restapi/verifier/operation"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/trustbloc/sandbox/pkg/internal/common/support"
	oidcclient "github.com/trustbloc/sandbox/pkg/restapi/internal/common/oidc"
)

const (
	httpContentTypeJSON = "application/json"

	// api paths
	verifyVPPath                  = "/verifyPresentation"
	oauth2GetRequestPath          = "/oauth2/request"
	oauth2CallbackPath            = "/oauth2/callback"
	oidcShareRequestPath          = "/oidc/share/request"
	oidcShareCallbackPath         = "/oidc/share/cb"
	verifyPresentationPath        = "/verify/presentation"
	verifyCredentialPath          = "/verify/credential" //nolint:gosec
	wellKnownConfigGetRequestPath = "/.well-known/did-configuration.json"
	openID4VPGetQRPath            = "/verify/openid4vp/getQR"
	openID4VPRetrieveClaimsQRPath = "/verify/openid4vp/retrieve"
	openID4VPWebhookPath          = "/verify/openid4vp/webhook"
	openID4VPWebhookCheckPath     = "/verify/openid4vp/webhook/check"

	// api path params
	scopeQueryParam    = "scope"
	flowQueryParam     = "flow"
	demoTypeQueryParam = "demoType"

	// edge-service verifier endpoints
	verifyPresentationURLFormat = "/%s" + "/verifier/presentations/verify"

	// edge-service verifier endpoints
	verifyCredentialURLFormat = "/%s" + "/verifier/credentials/verify"

	initiateOidcInteractionURLFormat   = "/verifier/profiles/%s/interactions/initiate-oidc"
	retrieveInteractionsClaimURLFormat = "/verifier/interactions/%s/claim"

	// TODO https://github.com/trustbloc/sandbox/issues/352 Configure verifier profiles in Verifier page
	verifierProfileID = "trustbloc-verifier"

	verifierJWTProfileID = "jwt-web-ED25519-JsonWebSignature2020"

	vcsVerifierRequestTokenName = "vcs_verifier" //nolint: gosec

	transientStoreName = "rp-rest-transient"
	flowTypeCookie     = "flowType"
	waciDemoType       = "waci"
)

var logger = log.New("sandbox-rp-restapi")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type oidcClient interface {
	CreateOIDCRequest(state, scope string) (string, error)
	HandleOIDCCallback(reqContext context.Context, code string) ([]byte, error)
}

type initiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxID                 string `json:"txID"`
}

// Operation defines handlers
type Operation struct {
	handlers        []Handler
	vpHTML          string
	didCommVpHTML   string
	oidcShareVpHTML string
	vcsURL          string
	vcsV1URL        string
	client          httpClient
	requestTokens   map[string]string
	transientStore  storage.Store
	tlsConfig       *tls.Config
	oidcClient      oidcClient
	waciOIDCClient  oidcClient
	walletAuthURL   string
	accessTokenURL  string
	apiGatewayURL   string
	eventsTopic     *EventsTopic
	didConfig       []byte
}

// Config defines configuration for rp operations
type Config struct {
	VPHTML                 string
	DIDCOMMVPHTML          string
	OIDCShareVPHTML        string
	VCSURL                 string
	VCSV1URL               string
	TLSConfig              *tls.Config
	RequestTokens          map[string]string
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCCallbackURL        string
	TransientStoreProvider storage.Provider
	WACIOIDCProviderURL    string
	WACIOIDCClientID       string
	WACIOIDCClientSecret   string
	WACIOIDCCallbackURL    string
	WalletAuthURL          string
	AccessTokenURL         string
	APIGatewayURL          string
}

// vc struct used to return vc data to html
type vc struct {
	Data     string `json:"data"`
	Msg      string `json:"msg"`
	FlowType string `json:"flowType"`
}

type createOIDCRequestResponse struct {
	Request  string `json:"request"`
	FlowType string `json:"flowType"`
}

type openID4VPGetQRResponse struct {
	QRText string `json:"qrText"`
	TxID   string `json:"txID"`
}

// New returns rp operation instance
func New(config *Config) (*Operation, error) {
	svc := &Operation{
		vpHTML:          config.VPHTML,
		didCommVpHTML:   config.DIDCOMMVPHTML,
		oidcShareVpHTML: config.OIDCShareVPHTML,
		vcsURL:          config.VCSURL,
		vcsV1URL:        config.VCSV1URL,
		client:          &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:   config.RequestTokens,
		tlsConfig:       config.TLSConfig,
		walletAuthURL:   config.WalletAuthURL,
		accessTokenURL:  config.AccessTokenURL,
		apiGatewayURL:   config.APIGatewayURL,
		eventsTopic:     NewEventsTopic(),
	}

	var err error

	svc.oidcClient, err = oidcclient.New(&oidcclient.Config{
		OIDCClientID:     config.OIDCClientID,
		OIDCClientSecret: config.OIDCClientSecret, OIDCCallbackURL: config.OIDCCallbackURL,
		OIDCProviderURL: config.OIDCProviderURL, TLSConfig: config.TLSConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc client : %w", err)
	}

	svc.waciOIDCClient, err = oidcclient.New(&oidcclient.Config{
		OIDCClientID:     config.WACIOIDCClientID,
		OIDCClientSecret: config.WACIOIDCClientSecret, OIDCCallbackURL: config.WACIOIDCCallbackURL,
		OIDCProviderURL: config.WACIOIDCProviderURL, TLSConfig: config.TLSConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc client : %w", err)
	}

	svc.transientStore, err = createStore(config.TransientStoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create store : %w", err)
	}

	svc.registerHandler()

	return svc, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(verifyVPPath, http.MethodPost, c.verifyVP),
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),

		support.NewHTTPHandler(oidcShareRequestPath, http.MethodPost, c.createOIDCShareRequest),
		support.NewHTTPHandler(oidcShareCallbackPath, http.MethodGet, c.handleOIDCShareCallback),

		support.NewHTTPHandler(verifyPresentationPath, http.MethodPost, c.verifyPresentation),
		support.NewHTTPHandler(verifyCredentialPath, http.MethodPost, c.verifyCredential),

		support.NewHTTPHandler(wellKnownConfigGetRequestPath, http.MethodGet, c.wellKnownConfig),
		support.NewHTTPHandler(openID4VPGetQRPath, http.MethodGet, c.openID4VPGetQR),
		support.NewHTTPHandler(openID4VPRetrieveClaimsQRPath, http.MethodGet, c.retrieveInteractionsClaim),

		support.NewHTTPHandler(openID4VPWebhookPath, http.MethodPost, c.eventsTopic.receiveTopics),
		support.NewHTTPHandler(openID4VPWebhookCheckPath, http.MethodGet, c.eventsTopic.checkTopics),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func (c *Operation) verifyPresentation(w http.ResponseWriter, r *http.Request) {
	req := &verifyPresentationRequest{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	vpReq := edgesvcops.VerifyPresentationRequest{
		Presentation: req.VP,
		Opts: &edgesvcops.VerifyPresentationOptions{
			Checks:    req.Checks,
			Challenge: req.Challenge,
			Domain:    req.Domain,
		},
	}

	resp, err := c.callVerifyPresentation(vpReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify vp: %s", err.Error()))

		return
	}

	if resp.StatusCode != http.StatusOK {
		respBytes, respErr := io.ReadAll(resp.Body)
		if respErr != nil {
			c.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("failed to read verify presentation resp : %s", err.Error()))

			return
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("closing response body failed: %v", e)
			}
		}()

		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to verify presentation: %s", string(respBytes)))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(""))
}

func (c *Operation) verifyCredential(w http.ResponseWriter, r *http.Request) {
	req := &verifyCredentialRequest{}

	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	vcReq := edgesvcops.CredentialsVerificationRequest{
		Credential: req.VC,
		Opts: &edgesvcops.CredentialsVerificationOptions{
			Checks: req.Checks,
		},
	}

	resp, err := c.callVerifyCredential(vcReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify vc: %s", err.Error()))

		return
	}

	if resp.StatusCode != http.StatusOK {
		respBytes, respErr := io.ReadAll(resp.Body)
		if respErr != nil {
			c.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("failed to read verify credentail resp : %s", err.Error()))

			return
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("closing response body failed: %v", e)
			}
		}()

		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to verify credential: %s", string(respBytes)))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(""))
}

// verifyVP
func (c *Operation) verifyVP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse form: %s", err.Error()))

		return
	}

	inputData := "vpDataInput"
	checks := strings.Split(r.Form.Get("checks"), ",")
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

	c.verify(req, inputData, c.vpHTML, w, r)
}

func (c *Operation) createOIDCShareRequest(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	oidcVpReq := &oidcVpRequest{}

	err := json.NewDecoder(r.Body).Decode(oidcVpReq)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request: %s", err.Error()))

		return
	}

	walletAuthURL := oidcVpReq.WalletAuthURL
	if walletAuthURL == "" {
		walletAuthURL = c.walletAuthURL
	}

	var pd *presexch.PresentationDefinition

	err = json.Unmarshal(oidcVpReq.PresentationDefinition, &pd)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to unmarshal presentation definition : %s", err))
		return
	}

	authClaims := &oidcAuthClaims{
		VPToken: &vpToken{
			PresDef: pd,
		},
	}

	claimsBytes, err := json.Marshal(authClaims)
	if err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to unmarshal invitation : %s", err))

		return
	}

	state := uuid.NewString()

	// TODO: use OIDC client library
	// construct wallet auth req with PEx
	walletReq, err := http.NewRequest("GET", walletAuthURL, nil)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get interaction data : %s", err))

		return
	}

	redirectURI := &url.URL{
		Scheme: r.URL.Scheme,
		Host:   r.Host,
		Path:   oidcShareCallbackPath,
	}

	q := walletReq.URL.Query()
	q.Add("client_id", "demo-verifier")
	q.Add("redirect_uri", redirectURI.String())
	q.Add("scope", "openid")
	q.Add("state", state)
	q.Add("claims", string(claimsBytes))

	walletReq.URL.RawQuery = q.Encode()

	redirectURL := walletReq.URL.String()

	err = c.savePresentationDefinition(pd, state)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed save presentation definition : %s", err))

		return
	}

	c.writeResponse(w, http.StatusOK, []byte(redirectURL))
}

func (c *Operation) savePresentationDefinition(pd *presexch.PresentationDefinition, state string) error {
	pdBytes, err := json.Marshal(pd)
	if err != nil {
		return fmt.Errorf("failed marshal presentation definition : %w", err)
	}

	err = c.transientStore.Put(state, pdBytes)
	if err != nil {
		return fmt.Errorf("failed store presentation definition : %w", err)
	}

	return nil
}

func (c *Operation) handleOIDCShareCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")

	pdBytes, err := c.transientStore.Get(state)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to get oidc state data : %s", err))

		return
	}

	var pd *presexch.PresentationDefinition

	err = json.Unmarshal(pdBytes, &pd)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to unmarshal presentation definition : %s", err))

		return
	}

	idToken := r.URL.Query().Get("id_token")
	vpToken := r.URL.Query().Get("vp_token")
	logger.Infof("oidc share callback : id_token=%s vp_token=%s",
		idToken, vpToken)

	var claims *oidcTokenClaims

	token, err := jwt.ParseSigned(idToken)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parsed token : %s", err))

		return
	}

	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to convert to claim object : %s", err))

		return
	}

	logger.Infof("oidc share callback : vp_token=%s", vpToken)

	_, err = verifiable.ParsePresentation([]byte(vpToken),
		verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(nil)),
		verifiable.WithPresDisabledProofCheck())

	if err != nil {
		logger.Errorf("failed to handle oidc share callback : %s vptoken %s", err, vpToken)
		c.oidcShareVpResult(w, fmt.Sprintf("failed to parse presentation: %s", err))

		return
	}

	c.oidcShareVpResult(w, "Successfully Received OIDC verifiable Presentation")
}

func (c *Operation) wellKnownConfig(w http.ResponseWriter, r *http.Request) {
	if len(c.didConfig) == 0 {
		// TODO make profile id configurable
		resp, err := c.sendHTTPRequest(http.MethodGet,
			fmt.Sprintf("%s/verifier/profiles/%s/well-known/did-config",
				c.vcsV1URL, verifierJWTProfileID), nil, httpContentTypeJSON, "")
		if err != nil {
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("failed to get did config: %s", err.Error()))

			return
		}

		respBytes, respErr := io.ReadAll(resp.Body)
		if respErr != nil {
			c.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("failed to read did config resp : %s", err.Error()))

			return
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("closing response body failed: %v", e)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			c.writeErrorResponse(w, http.StatusInternalServerError,
				fmt.Sprintf("did config didn't return 200 status: %s", string(respBytes)))

			return
		}

		c.didConfig = respBytes
	}

	w.Header().Set("content-type", httpContentTypeJSON)

	_, err := w.Write(c.didConfig)
	if err != nil {
		logger.Errorf("failed to write response : %s", err)
	}
}

func (c *Operation) openID4VPGetQR(w http.ResponseWriter, r *http.Request) { //nolint: funlen
	// TODO make username and secret configurable
	token, err := c.issueAccessToken(c.accessTokenURL, "test-org", "test-org-secret", []string{"org_admin"})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to issue token : %s", err))

		return
	}

	endpoint := fmt.Sprintf(initiateOidcInteractionURLFormat, verifierJWTProfileID)

	resp, err := c.sendHTTPRequest(http.MethodPost,
		c.apiGatewayURL+endpoint, nil, httpContentTypeJSON, token)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to initiate oidc: %s", err.Error()))

		return
	}

	respBytes, respErr := io.ReadAll(resp.Body)
	if respErr != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to read initiate oidc resp : %s", err.Error()))

		return
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("closing response body failed: %v", e)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("initiate oidc didn't return 200 status: %s", string(respBytes)))

		return
	}

	result := &initiateOIDC4VPResponse{}

	if err = json.Unmarshal(respBytes, result); err != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to unmarshal initiate oidc response : %s", err))

		return
	}

	response, err := json.Marshal(&openID4VPGetQRResponse{
		QRText: result.AuthorizationRequest,
		TxID:   result.TxID,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal response : %s", err))

		return
	}

	w.Header().Set("content-type", httpContentTypeJSON)

	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write response : %s", err)
	}
}

func (c *Operation) retrieveInteractionsClaim(w http.ResponseWriter, r *http.Request) {
	// TODO make username and secret configurable
	token, err := c.issueAccessToken(c.accessTokenURL, "test-org", "test-org-secret", []string{"org_admin"})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to issue token : %s", err))

		return
	}

	endpoint := fmt.Sprintf(retrieveInteractionsClaimURLFormat, r.URL.Query().Get("tx"))

	resp, err := c.sendHTTPRequest(http.MethodGet,
		c.apiGatewayURL+endpoint, nil, "", token)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to initiate oidc: %s", err.Error()))

		return
	}

	respBytes, respErr := io.ReadAll(resp.Body)
	if respErr != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to read initiate oidc resp : %s", err.Error()))

		return
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("closing response body failed: %v", e)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("retrieve interactions claim %s didn't return 200 status: %s",
				c.apiGatewayURL+endpoint, string(respBytes)))

		return
	}

	w.Header().Set("content-type", httpContentTypeJSON)

	_, err = w.Write(respBytes)
	if err != nil {
		logger.Errorf("failed to write response : %s", err)
	}
}

func (c *Operation) createOIDCRequest(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	scope := r.URL.Query().Get(scopeQueryParam)
	if scope == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing scope")

		return
	}

	flowType := r.URL.Query().Get(flowQueryParam)
	if flowType == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing flow type")

		return
	}

	demoType := r.URL.Query().Get(demoTypeQueryParam)

	// TODO validate scope
	state := uuid.New().String()

	adapterOIDCClient := c.oidcClient

	if demoType == waciDemoType {
		adapterOIDCClient = c.waciOIDCClient
	}

	redirectURL, err := adapterOIDCClient.CreateOIDCRequest(state, scope)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to create oidc request : %s", err))

		return
	}

	response, err := json.Marshal(&createOIDCRequestResponse{
		Request:  redirectURL,
		FlowType: flowType,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal response : %s", err))

		return
	}

	err = c.transientStore.Put(state, []byte(demoType))
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write state to transient store : %s", err))

		return
	}

	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{Name: flowTypeCookie, Value: flowType, Expires: expire}
	http.SetCookie(w, &cookie)

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
		c.didcommDemoResult(w, "missing state", "")

		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Errorf("missing code")
		c.didcommDemoResult(w, "missing code", "")

		return
	}

	flowTypeCookie, err := r.Cookie(flowTypeCookie)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		logger.Errorf(err.Error())
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get flowType cookie: %s",
			err.Error()))

		return
	}

	demoType, err := c.transientStore.Get(state)
	if errors.Is(err, storage.ErrDataNotFound) {
		logger.Errorf("invalid state parameter")
		c.didcommDemoResult(w, "invalid state parameter", "")

		return
	}

	if err != nil {
		logger.Errorf("failed to query transient store for state : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to query transient store for state : %s", err), "")

		return
	}

	adapterOIDCClient := c.oidcClient
	if string(demoType) == waciDemoType {
		adapterOIDCClient = c.waciOIDCClient
	}

	data, err := adapterOIDCClient.HandleOIDCCallback(r.Context(), code)
	if err != nil {
		logger.Errorf("failed to handle oidc callback : %s", err)
		c.didcommDemoResult(w, fmt.Sprintf("failed to handle oidc callback: %s", err), "")

		return
	}

	c.didcommDemoResult(w, string(data), flowTypeCookie.Value)
}

func (c *Operation) oidcShareVpResult(w http.ResponseWriter, msg string) {
	t, err := template.ParseFiles(c.oidcShareVpHTML)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, vc{Msg: msg}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) didcommDemoResult(w http.ResponseWriter, data, flowType string) {
	t, err := template.ParseFiles(c.didCommVpHTML)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, vc{Data: data, FlowType: flowType}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

// verify function verifies the input data and parse the response to provided template
func (c *Operation) verify(verifyReq interface{}, inputData, htmlTemplate string,
	w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(htmlTemplate)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to load html: %s", err.Error()))

		return
	}

	resp, httpErr := c.callVerifyPresentation(verifyReq)
	if httpErr != nil {
		c.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("failed to verify: %s", httpErr.Error()))

		if err := t.Execute(w, vc{Msg: "Oops verification is failed, Try again"}); err != nil {
			logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
		}

		return
	}

	if resp.StatusCode != http.StatusOK { //nolint:nestif
		var failedMsg string

		respBytes, respErr := io.ReadAll(resp.Body)
		if respErr != nil {
			failedMsg = fmt.Sprintf("failed to read response body: %s", respErr)
		} else {
			failedMsg = string(respBytes)
			isStatusRevoked := checkVCStatus(failedMsg, w, t)
			if isStatusRevoked {
				return
			}
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

	if err := t.Execute(w, vc{Msg: "Successfully verified", Data: r.Form.Get(inputData)}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (c *Operation) callVerifyPresentation(verifyReq interface{}) (*http.Response, error) {
	endpoint := fmt.Sprintf(verifyPresentationURLFormat, verifierProfileID)

	reqBytes, err := json.Marshal(verifyReq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal request : %w", err)
	}

	return c.sendHTTPRequest(http.MethodPost, c.vcsURL+endpoint, reqBytes, httpContentTypeJSON,
		c.requestTokens[vcsVerifierRequestTokenName])
}

func (c *Operation) callVerifyCredential(verifyReq interface{}) (*http.Response, error) {
	endpoint := fmt.Sprintf(verifyCredentialURLFormat, verifierProfileID)

	reqBytes, err := json.Marshal(verifyReq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal request : %w", err)
	}

	return c.sendHTTPRequest(http.MethodPost, c.vcsURL+endpoint, reqBytes, httpContentTypeJSON,
		c.requestTokens[vcsVerifierRequestTokenName])
}

func checkVCStatus(failedMsg string, rw io.Writer, t *template.Template) bool {
	isStatusRevoked := checkSubstrings(failedMsg, "Revoked")

	if isStatusRevoked {
		if err := t.Execute(rw, vc{Msg: "Oops verification is failed. VC is revoked"}); err != nil {
			logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
		}
	}

	return isStatusRevoked
}

func checkSubstrings(str string, subs ...string) bool {
	isCompleteMatch := false

	for _, sub := range subs {
		if strings.Contains(str, sub) {
			isCompleteMatch = true
		}
	}

	return isCompleteMatch
}

func (c *Operation) sendHTTPRequest(method, reqURL string, body []byte, contentType,
	token string) (*http.Response, error) {
	logger.Infof("send http request : url=%s methdod=%s body=%s", reqURL, method, string(body))

	req, err := http.NewRequest(method, reqURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	} else {
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

	write := rw.Write
	if _, err := write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

func createStore(p storage.Provider) (storage.Store, error) {
	return p.OpenStore(transientStoreName)
}

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw http.ResponseWriter, status int, data []byte) {
	rw.WriteHeader(status)

	if _, err := rw.Write(data); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// issueAccessToken issue token.
func (c *Operation) issueAccessToken(oidcProviderURL, clientID, secret string, scopes []string) (string, error) {
	conf := clientcredentials.Config{
		TokenURL:     oidcProviderURL + "/oauth2/token",
		ClientID:     clientID,
		ClientSecret: secret,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig,
		},
	})

	token, err := conf.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.AccessToken, nil
}
