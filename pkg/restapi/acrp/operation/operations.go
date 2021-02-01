/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
)

const (
	// api paths
	register = "/register"
	login    = "/login"

	// store
	txnStoreName = "issuer_txn"
)

var logger = log.New("acrp-restapi")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers.
type Operation struct {
	store         storage.Store
	handlers      []Handler
	dashboardHTML string
}

// Config config.
type Config struct {
	StoreProvider storage.Provider
	DashboardHTML string
}

// New returns acrp operation instance.
func New(config *Config) (*Operation, error) {
	store, err := getTxnStore(config.StoreProvider)
	if err != nil {
		return nil, fmt.Errorf("acrp store provider : %w", err)
	}

	op := &Operation{
		store:         store,
		dashboardHTML: config.DashboardHTML,
	}

	op.registerHandler()

	return op, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (o *Operation) registerHandler() {
	o.handlers = []Handler{
		support.NewHTTPHandler(register, http.MethodPost, o.register),
		support.NewHTTPHandler(login, http.MethodPost, o.login),
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

	// TODO call TrustBloc services and save nationalID in EDV
	logger.Infof("nationalID=%s", r.FormValue("nationalID"))

	err = o.store.Put(r.FormValue("username"), []byte(r.FormValue("password")))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to save user data: %s", err.Error()))

		return
	}

	o.loadHTML(w, o.dashboardHTML, map[string]interface{}{
		"UserName": r.FormValue("username"),
	})
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

	o.loadHTML(w, o.dashboardHTML, map[string]interface{}{
		"UserName": r.FormValue("username"),
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
