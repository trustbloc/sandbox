/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/tls"
	"fmt"
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
)

const (
	adminURLEnvKey     = "ADMIN_URL"
	servePortEnvKey    = "SERVE_PORT"
	skipSSLCheckEnvKey = "SKIP_SSL_CHECK"

	loginHTML   = "./templates/login.html"
	consentHTML = "./templates/consent.html"

	timeout = 10 * time.Second
)

func main() {
	adminURL := os.Getenv(adminURLEnvKey)
	if adminURL == "" {
		panic("admin URL is required")
	}

	port := os.Getenv(servePortEnvKey)
	if port == "" {
		panic("port to be served not provided")
	}

	var skipSSLCheck bool

	skipSSLCheckVal := os.Getenv(skipSSLCheckEnvKey)
	if skipSSLCheckVal != "" {
		var err error

		skipSSLCheck, err = strconv.ParseBool(skipSSLCheckVal)
		if err != nil {
			fmt.Printf("Invalid value (%s) suppiled for `%s`, switching to default false", skipSSLCheckVal, skipSSLCheckEnvKey)
		}
	}

	c, err := newConsentServer(adminURL, skipSSLCheck)
	if err != nil {
		panic(err)
	}

	// Hydra login and consent handlers
	http.HandleFunc("/login", c.login)
	http.HandleFunc("/consent", c.consent)

	fmt.Println(http.ListenAndServe(":"+port, nil))
}

// newConsentServer returns new login consent server instance
func newConsentServer(adminURL string, skipSSLCheck bool) (*consentServer, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}

	loginTemplate, err := template.ParseFiles(loginHTML)
	if err != nil {
		return nil, err
	}

	consentTemplate, err := template.ParseFiles(consentHTML)
	if err != nil {
		return nil, err
	}

	return &consentServer{
		hydraClient: client.NewHTTPClientWithConfig(nil,
			&client.TransportConfig{Schemes: []string{u.Scheme}, Host: u.Host, BasePath: u.Path}),
		loginTemplate:   loginTemplate,
		consentTemplate: consentTemplate,
		skipSSLCheck:    skipSSLCheck,
	}, nil
}

// ConsentServer hydra login consent server
type consentServer struct {
	hydraClient     *client.OryHydra
	loginTemplate   *template.Template
	consentTemplate *template.Template
	skipSSLCheck    bool
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

	httpclient := &http.Client{}
	if c.skipSSLCheck {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	loginRqstParams := admin.NewGetLoginRequestParamsWithHTTPClient(httpclient)
	loginRqstParams.SetTimeout(timeout)
	loginRqstParams.LoginChallenge = challenge[0]

	resp, err := c.hydraClient.Admin.GetLoginRequest(loginRqstParams)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	loginOKRequest := admin.NewAcceptLoginRequestParamsWithHTTPClient(httpclient)

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
	httpclient := &http.Client{}
	if c.skipSSLCheck {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// get the consent request
	consentRqstParams := admin.NewGetConsentRequestParamsWithHTTPClient(httpclient)
	consentRqstParams.SetTimeout(timeout)
	consentRqstParams.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentRequest, err := c.hydraClient.Admin.GetConsentRequest(consentRqstParams)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	fullData := map[string]interface{}{
		"User":       consentRequest.Payload.Subject,
		"ClientName": consentRequest.Payload.Client.ClientName,
		"ClientID":   consentRequest.Payload.Client.ClientID,
		"Challenge":  consentRqstParams.ConsentChallenge,
		"Scope":      consentRequest.Payload.RequestedScope,
	}

	err = c.consentTemplate.Execute(w, fullData)
	if err != nil {
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (c *consentServer) acceptConsentRequest(w http.ResponseWriter, req *http.Request) {
	httpclient := &http.Client{}
	if c.skipSSLCheck {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	getConsentRequest := admin.NewGetConsentRequestParamsWithHTTPClient(httpclient)
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

	consentOKRequest := admin.NewAcceptConsentRequestParamsWithHTTPClient(httpclient)
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
	httpclient := &http.Client{}
	if c.skipSSLCheck {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	consentDeniedRequest := admin.NewRejectConsentRequestParamsWithHTTPClient(httpclient)

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
