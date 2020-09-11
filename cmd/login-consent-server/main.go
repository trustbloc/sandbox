/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

const (
	adminURLEnvKey          = "ADMIN_URL"
	servePortEnvKey         = "SERVE_PORT"
	tlsSystemCertPoolEnvKey = "TLS_SYSTEMCERTPOOL"
	tlsCACertsEnvKey        = "TLS_CACERTS"
	loginConsentMode        = "LOGIN_CONSENT_MODE"

	loginHTML       = "./templates/login.html"
	consentHTML     = "./templates/consent.html"
	bankloginHTML   = "./templates/banklogin.html"
	bankconsentHTML = "./templates/bankconsent.html"

	timeout = 10 * time.Second
)

func main() {
	c, err := buildConsentServer()
	if err != nil {
		panic(err)
	}

	port := os.Getenv(servePortEnvKey)
	if port == "" {
		panic("port to be served not provided")
	}

	// Hydra login and consent handlers
	http.HandleFunc("/login", c.login)
	http.HandleFunc("/consent", c.consent)

	http.Handle("/img/", http.FileServer(http.Dir("templates")))

	fmt.Println(http.ListenAndServe(":"+port, nil))
}

func buildConsentServer() (*consentServer, error) {
	adminURL := os.Getenv(adminURLEnvKey)
	if adminURL == "" {
		return nil, fmt.Errorf("admin URL is required")
	}

	var tlsSystemCertPool bool

	tlsSystemCertPoolVal := os.Getenv(tlsSystemCertPoolEnvKey)
	if tlsSystemCertPoolVal != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolVal)
		if err != nil {
			return nil, fmt.Errorf("invalid value (%s) suppiled for `%s`, switching to default false",
				tlsSystemCertPoolVal, tlsSystemCertPoolEnvKey)
		}
	}

	var tlsCACerts []string

	tlsCACertsVal := os.Getenv(tlsCACertsEnvKey)
	if tlsCACertsVal != "" {
		tlsCACerts = strings.Split(tlsCACertsVal, ",")
	}

	loginConsentModeVal := os.Getenv(loginConsentMode)
	if loginConsentModeVal == "bank" {
		return newConsentServer(adminURL, bankloginHTML, bankconsentHTML, tlsSystemCertPool, tlsCACerts)
	}

	return newConsentServer(adminURL, loginHTML, consentHTML, tlsSystemCertPool, tlsCACerts)
}

// newConsentServer returns new login consent server instance
func newConsentServer(adminURL, loginHTMLPath, consentHTMLPath string, tlsSystemCertPool bool,
	tlsCACerts []string) (*consentServer, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}

	loginTemplate, err := template.ParseFiles(loginHTMLPath)
	if err != nil {
		return nil, err
	}

	consentTemplate, err := template.ParseFiles(consentHTMLPath)
	if err != nil {
		return nil, err
	}

	rootCAs, err := tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
	if err != nil {
		return nil, err
	}

	return &consentServer{
		hydraClient: client.NewHTTPClientWithConfig(nil,
			&client.TransportConfig{Schemes: []string{u.Scheme}, Host: u.Host, BasePath: u.Path}),
		loginTemplate:   loginTemplate,
		consentTemplate: consentTemplate,
		httpClient:      &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}},
	}, nil
}

// ConsentServer hydra login consent server
type consentServer struct {
	hydraClient     *client.OryHydra
	loginTemplate   *template.Template
	consentTemplate *template.Template
	httpClient      *http.Client
}

func (c *consentServer) login(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		challenge := req.URL.Query().Get("login_challenge")
		fullData := map[string]interface{}{
			"login_challenge": challenge,
		}

		err := c.loginTemplate.Execute(w, fullData)
		if err != nil {
			fmt.Fprint(w, err.Error())
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
	case "POST":
		c.acceptLoginRequest(w, req)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *consentServer) consent(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		c.showConsentPage(w, req)
		return
	case "POST":
		ok := parseRequestForm(w, req)
		if !ok {
			return
		}

		allowed, found := req.Form["submit"]
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "consent value missing, Bad request!")

			return
		}

		switch allowed[0] {
		case "accept":
			c.acceptConsentRequest(w, req)
			return
		case "reject":
			c.rejectConsentRequest(w, req)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "incorrect consent value, Bad request!")

			return
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *consentServer) acceptLoginRequest(w http.ResponseWriter, req *http.Request) {
	ok := parseRequestForm(w, req)
	if !ok {
		return
	}

	username, usernameSet := req.Form["email"]
	password, passwordSet := req.Form["password"]
	challenge, challengeSet := req.Form["challenge"]

	if !usernameSet || !passwordSet || !challengeSet || !c.authLogin(username[0], password[0]) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	loginRqstParams := admin.NewGetLoginRequestParamsWithHTTPClient(c.httpClient)
	loginRqstParams.SetTimeout(timeout)
	loginRqstParams.LoginChallenge = challenge[0]

	resp, err := c.hydraClient.Admin.GetLoginRequest(loginRqstParams)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	loginOKRequest := admin.NewAcceptLoginRequestParamsWithHTTPClient(c.httpClient)

	b := &models.AcceptLoginRequest{
		Subject: &username[0],
	}

	loginOKRequest.SetBody(b)
	loginOKRequest.SetTimeout(timeout)
	loginOKRequest.LoginChallenge = resp.Payload.Challenge

	loginOKResponse, err := c.hydraClient.Admin.AcceptLoginRequest(loginOKRequest)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	http.Redirect(w, req, loginOKResponse.Payload.RedirectTo, http.StatusFound)
}

func (c *consentServer) showConsentPage(w http.ResponseWriter, req *http.Request) {
	// get the consent request
	consentRqstParams := admin.NewGetConsentRequestParamsWithHTTPClient(c.httpClient)
	consentRqstParams.SetTimeout(timeout)
	consentRqstParams.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentRequest, err := c.hydraClient.Admin.GetConsentRequest(consentRqstParams)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fullData := map[string]interface{}{
		"User":      consentRequest.Payload.Subject,
		"Challenge": consentRqstParams.ConsentChallenge,
		"Scope":     consentRequest.Payload.RequestedScope,
	}

	if consentRequest.Payload.Client != nil {
		fullData["ClientName"] = consentRequest.Payload.Client.ClientName
		fullData["ClientID"] = consentRequest.Payload.Client.ClientID
	}

	err = c.consentTemplate.Execute(w, fullData)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (c *consentServer) acceptConsentRequest(w http.ResponseWriter, req *http.Request) {
	getConsentRequest := admin.NewGetConsentRequestParamsWithHTTPClient(c.httpClient)
	getConsentRequest.SetTimeout(timeout)
	getConsentRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	getConsentRequestResponse, err := c.hydraClient.Admin.GetConsentRequest(getConsentRequest)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	_, remember := req.Form["remember"]
	b := &models.AcceptConsentRequest{
		GrantScope:               req.Form["grant_scope"],
		GrantAccessTokenAudience: getConsentRequestResponse.Payload.RequestedAccessTokenAudience,
		Remember:                 remember,
		HandledAt:                strfmt.DateTime(time.Now()),
	}

	consentOKRequest := admin.NewAcceptConsentRequestParamsWithHTTPClient(c.httpClient)
	consentOKRequest.SetBody(b)
	consentOKRequest.SetTimeout(timeout)
	consentOKRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentOKResponse, err := c.hydraClient.Admin.AcceptConsentRequest(consentOKRequest)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	http.Redirect(w, req, consentOKResponse.Payload.RedirectTo, http.StatusFound)
}

func (c *consentServer) rejectConsentRequest(w http.ResponseWriter, req *http.Request) {
	consentDeniedRequest := admin.NewRejectConsentRequestParamsWithHTTPClient(c.httpClient)

	b := &models.RejectRequest{
		Error:            "access_denied",
		ErrorDescription: "The resource owner denied the request",
	}

	consentDeniedRequest.SetBody(b)
	consentDeniedRequest.SetTimeout(timeout)
	consentDeniedRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentDenyResponse, err := c.hydraClient.Admin.RejectConsentRequest(consentDeniedRequest)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	http.Redirect(w, req, consentDenyResponse.Payload.RedirectTo, http.StatusFound)
}

// authLogin authenticates user login credentials,
// currently authenticating all users
func (c *consentServer) authLogin(usr, pwd string) bool {
	return true
}

// parseRequestForm parses request form.
// writes error to response and returns false when failed.
func parseRequestForm(w http.ResponseWriter, req *http.Request) bool {
	err := req.ParseForm()
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusBadRequest)

		return false
	}

	return true
}
