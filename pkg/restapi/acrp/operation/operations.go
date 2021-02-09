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
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	edgesvcops "github.com/trustbloc/edge-service/pkg/restapi/issuer/operation"

	"github.com/trustbloc/sandbox/pkg/internal/common/support"
)

const (
	// api paths
	register   = "/register"
	login      = "/login"
	connect    = "/connect"
	disconnect = "/disconnect"

	// store
	txnStoreName = "issuer_txn"

	// form param
	username   = "username"
	password   = "password"
	nationalID = "nationalID"

	vcsIssuerRequestTokenName = "vcs_issuer"

	// external paths
	issueCredentialURLFormat = "%s" + "/credentials/issueCredential"

	// json-ld
	credentialContext = "https://www.w3.org/2018/credentials/v1"
)

var logger = log.New("acrp-restapi")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers.
type Operation struct {
	store          storage.Store
	handlers       []Handler
	dashboardHTML  string
	httpClient     httpClient
	vaultServerURL string
	vcIssuerURL    string
	requestTokens  map[string]string
}

// Config config.
type Config struct {
	StoreProvider  storage.Provider
	DashboardHTML  string
	TLSConfig      *tls.Config
	VaultServerURL string
	VCIssuerURL    string
	RequestTokens  map[string]string
}

// New returns acrp operation instance.
func New(config *Config) (*Operation, error) {
	store, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, fmt.Errorf("acrp store provider : %w", err)
	}

	op := &Operation{
		store:          store,
		dashboardHTML:  config.DashboardHTML,
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		vaultServerURL: config.VaultServerURL,
		vcIssuerURL:    config.VCIssuerURL,
		requestTokens:  config.RequestTokens,
	}

	op.registerHandler()

	return op, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (o *Operation) registerHandler() {
	o.handlers = []Handler{
		support.NewHTTPHandler(register, http.MethodPost, o.register),
		support.NewHTTPHandler(login, http.MethodPost, o.login),
		support.NewHTTPHandler(connect, http.MethodGet, o.connect),
		support.NewHTTPHandler(disconnect, http.MethodGet, o.disconnect),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return o.handlers
}

func (o *Operation) register(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	pwd, err := o.store.Get(r.FormValue(username))
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to get user data: %s", err.Error()))

		return
	}

	if pwd != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "username already exists")

		return
	}

	// create vault for the user
	url := o.vaultServerURL + "/vaults"

	_, err = o.sendHTTPRequest(http.MethodPost, url, nil, http.StatusCreated, o.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create vault - url:%s err:%s", url, err.Error()))

		return
	}

	url = fmt.Sprintf(issueCredentialURLFormat, o.vcIssuerURL)

	// TODO - replace sub with vault DID
	vcReq, err := createNationalIDCred("sub", r.FormValue(nationalID))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create vc request: %s", err.Error()))
	}

	_, err = o.sendHTTPRequest(http.MethodPost, url, vcReq, http.StatusCreated, o.requestTokens[vcsIssuerRequestTokenName])
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create vc - url:%s err:%s", url, err.Error()))

		return
	}

	// TODO save the VC in vault server

	err = o.store.Put(r.FormValue(username), []byte(r.FormValue(password)))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to save user data: %s", err.Error()))

		return
	}

	o.showDashboard(w, r.FormValue(username), false)
}

func (o *Operation) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	pwd, err := o.store.Get(r.FormValue(username))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to get user data: %s", err.Error()))

		return
	}

	if r.FormValue(password) != string(pwd) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid password")

		return
	}

	o.showDashboard(w, r.FormValue(username), true)
}

func (o *Operation) connect(w http.ResponseWriter, r *http.Request) {
	userName := r.URL.Query()["userName"]
	if len(userName) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing username")

		return
	}

	// TODO connect with other service / integrate trustbloc features

	o.showDashboard(w, userName[0], true)
}

func (o *Operation) disconnect(w http.ResponseWriter, r *http.Request) {
	userName := r.URL.Query()["userName"]
	if len(userName) == 0 {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing username")

		return
	}

	// TODO disconnect with other service / integrate trustbloc features

	o.showDashboard(w, userName[0], false)
}

func (o *Operation) showDashboard(w http.ResponseWriter, userName string, serviceLinked bool) {
	url := fmt.Sprintf("/connect?userName=%s", userName)
	if serviceLinked {
		url = fmt.Sprintf("/disconnect?userName=%s", userName)
	}

	o.loadHTML(w, o.dashboardHTML, map[string]interface{}{
		"UserName":      userName,
		"ServiceLinked": serviceLinked,
		"URL":           url,
	})
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

// nolint: unparam
func (o *Operation) sendHTTPRequest(method, url string, reqBody []byte, status int, httpToken string) ([]byte, error) {
	logger.Errorf("sendHTTPRequest: method=%s url=%s reqBody=%s", method, url, string(reqBody))

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
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

	logger.Errorf("httpResponse: status=%d respBody=%s", resp.StatusCode, string(respBody))

	if resp.StatusCode != status {
		return nil, fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}

func createNationalIDCred(sub, nationalID string) ([]byte, error) {
	if nationalID == "" {
		return nil, errors.New("nationalID is mandatory")
	}

	cred := verifiable.Credential{}
	cred.Context = []string{credentialContext}
	cred.Types = []string{"VerifiableCredential"}
	// issuerID will be overwritten in the issuer
	cred.Issuer = verifiable.Issuer{ID: uuid.New().URN()}
	cred.Issued = util.NewTime(time.Now().UTC())

	credentialSubject := make(map[string]interface{})
	credentialSubject["id"] = sub
	credentialSubject[nationalID] = nationalID

	cred.Subject = credentialSubject

	credBytes, err := cred.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	return json.Marshal(edgesvcops.IssueCredentialRequest{
		Credential: credBytes,
	})
}
