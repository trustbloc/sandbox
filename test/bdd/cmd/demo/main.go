/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/btcsuite/btcutil/base58"
	"github.com/square/go-jose/v3"
)

// comparatorConfig
type comparatorConfig struct {
	DID  string            `json:"did"`
	Keys []json.RawMessage `json:"keys"`
}

type configOutput struct {
	DID        string `json:"did"`
	PrivateKey string `json:"privateKey"`
	KeyID      string `json:"keyID"`
}

func main() {
	//nolint: gosec
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	switch os.Args[1] { //nolint: gocritic
	case "comparator":
		switch os.Args[2] { //nolint: gocritic
		case "getConfig":
			req, err := http.NewRequest(http.MethodPost, os.Args[3], nil)
			if err != nil {
				fmt.Printf("failed to create new request: %s\n", err)
				return
			}

			resp, err := sendHTTPRequest(httpClient, req, http.StatusOK)
			if err != nil {
				fmt.Printf("failed to send http request: %s\n", err)
				return
			}

			var config comparatorConfig
			if errUnmarshal := json.Unmarshal(resp, &config); errUnmarshal != nil {
				fmt.Printf("failed to unmarshal resp to config: %s\n", errUnmarshal)
				return
			}

			jwk := jose.JSONWebKey{}
			if errUnmarshalJSON := jwk.UnmarshalJSON(config.Keys[0]); errUnmarshalJSON != nil {
				fmt.Printf("failed to unmarshal resp to jwk: %s\n", errUnmarshalJSON)
				return
			}

			k, ok := jwk.Key.(ed25519.PrivateKey)
			if !ok {
				fmt.Printf("key is not ed25519\n")
				return
			}

			bytes, err := json.Marshal(configOutput{DID: config.DID, PrivateKey: base58.Encode(k),
				KeyID: fmt.Sprintf("%s#%s", config.DID, jwk.KeyID)})
			if err != nil {
				fmt.Printf("failed to marshal: %s\n", err)
				return
			}

			fmt.Println(string(bytes))
		}
	}
}

func sendHTTPRequest(httpClient *http.Client, req *http.Request, status int) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			fmt.Println("failed to close response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
