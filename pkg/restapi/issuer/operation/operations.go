/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/trustbloc/edge-sandbox/pkg/internal/common/support"
	"github.com/trustbloc/edge-sandbox/pkg/token"
)

const (
	login    = "/login"
	callback = "/callback"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers for authorization service
type Operation struct {
	handlers      []Handler
	tokenIssuer   tokenIssuer
	tokenResolver tokenResolver
	cmsURL        string
}

// Config defines configuration for issuer operations
type Config struct {
	TokenIssuer   tokenIssuer
	TokenResolver tokenResolver
	CMSURL        string
}

type tokenIssuer interface {
	AuthCodeURL(w http.ResponseWriter) string
	Exchange(r *http.Request) (*oauth2.Token, error)
	Client(ctx context.Context, t *oauth2.Token) *http.Client
}

type tokenResolver interface {
	Resolve(token string) (*token.Introspection, error)
}

// New returns authorization instance
func New(config *Config) *Operation {
	svc := &Operation{
		tokenIssuer:   config.TokenIssuer,
		tokenResolver: config.TokenResolver,
		cmsURL:        config.CMSURL}
	svc.registerHandler()

	return svc
}

// Login using oauth2, will redirect to Auth Code URL
func (c *Operation) Login(w http.ResponseWriter, r *http.Request) {
	u := c.tokenIssuer.AuthCodeURL(w)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// Callback for oauth2 login
func (c *Operation) Callback(w http.ResponseWriter, r *http.Request) {
	tk, err := c.tokenIssuer.Exchange(r)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to exchange code for token: %s", err.Error()))

		return
	}

	// user info from token will be used for to retrieve data from cms
	ti, err := c.tokenResolver.Resolve(tk.AccessToken)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get token info: %s", err.Error()))

		return
	}

	log.Info(ti)

	_, err = c.getCMSData(tk)
	if err != nil {
		log.Error(err)
		c.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to get user cms data: %s", err.Error()))

		return
	}

	// get user data from CMS here (hard-code vc for now)
	c.writeResponse(w, validCredential)
}

func (c *Operation) getCMSData(tk *oauth2.Token) ([]byte, error) {
	httpClient := c.tokenIssuer.Client(context.Background(), tk)

	req, err := http.NewRequest("GET", c.cmsURL+"/studentcards/1", nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Warn("failed to close response body")
		}
	}()

	return ioutil.ReadAll(resp.Body)
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(login, http.MethodGet, c.Login),
		support.NewHTTPHandler(callback, http.MethodGet, c.Callback),
	}
}

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	// as of now, just log errors for writing response
	if err != nil {
		log.Errorf("Unable to send json response, %s", err)
	}
}

// writeResponse writes interface value to response
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

//nolint:lll
const validCredential = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://example.com/jdoe/keys/1",
    "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMBBn2h9hfcGZrvnC1b6PgWmukzFJ1IiH1dWgnDIS81BH-IxXnPkbuYDeySorc4QU9MJxdVkY5EL4HYbcIfwKj6X4LBQ2_ZHZIu1jdqLcRZqHcsDF5KKylKc1THn5VRWy5WhYg_gBnyWny8E6Qkrze53MR7OuAmmNJ1m1nN8SxDrG6a08L78J0-Fbas5OjAQz3c17GY8mVuDPOBIOVjMEghBlgl3nOi1ysxbRGhHLEK4s0KKbeRogZdgt1DkQxDFxxn41QWDw_mmMCjs9qxg0zcZzqEJw"
  },
  "expirationDate": "2020-01-01T19:23:24Z",
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  }
}
`
