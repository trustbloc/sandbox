/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
)

const (
	// api paths
	register   = "/register"
	login      = "/login"
	connect    = "/connect"
	disconnect = "/disconnect"

	// store
	txnStoreName = "issuer_txn"
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
}

// Config config.
type Config struct {
	StoreProvider  storage.Provider
	DashboardHTML  string
	TLSConfig      *tls.Config
	VaultServerURL string
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
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	password, err := o.store.Get(r.FormValue("username"))
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to get user data: %s", err.Error()))

		return
	}

	if password != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "username already exists")

		return
	}

	// create vault for the user
	url := o.vaultServerURL + "/vaults"

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		logger.Errorf("failed to create create vault http request: %s", err.Error())
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create create vault http request: %s", err.Error()))

		return
	}

	// TODO save vault related details
	_, err = sendHTTPRequest(req, o.httpClient, http.StatusCreated)
	if err != nil {
		logger.Errorf("failed to create vault - url:%s err:%s", url, err.Error())
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to create vault - url:%s err:%s", url, err.Error()))

		return
	}

	// TODO create VC for nationalID
	logger.Infof("nationalID=%s", r.FormValue("nationalID"))

	// TODO call comparator service and save the VC

	err = o.store.Put(r.FormValue("username"), []byte(r.FormValue("password")))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to save user data: %s", err.Error()))

		return
	}

	o.showDashboard(w, r.FormValue("username"), false)
}

func (o *Operation) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to parse form data: %s", err.Error()))

		return
	}

	password, err := o.store.Get(r.FormValue("username"))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unable to get user data: %s", err.Error()))

		return
	}

	if r.FormValue("password") != string(password) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid password")

		return
	}

	o.showDashboard(w, r.FormValue("username"), true)
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

func sendHTTPRequest(req *http.Request, client httpClient, status int) ([]byte, error) {
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
