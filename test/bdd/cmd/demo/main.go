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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/edge-service/pkg/client/comparator/client"
	"github.com/trustbloc/edge-service/pkg/client/comparator/client/operations"
)

const (
	requestTimeout = 20 * time.Second
)

type configOutput struct {
	DID        string `json:"did"`
	PrivateKey string `json:"privateKey"`
	KeyID      string `json:"keyID"`
}

func main() { //nolint: funlen
	switch os.Args[1] { //nolint: gocritic
	case "comparator":
		switch os.Args[2] { //nolint: gocritic
		case "getConfig":
			//nolint: gosec
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			comparatorURL := strings.Split(os.Args[3], "://")

			transport := httptransport.NewWithClient(
				comparatorURL[1],
				client.DefaultBasePath,
				[]string{comparatorURL[0]},
				httpClient,
			)

			c := client.New(transport, strfmt.Default)

			config, err := c.Operations.GetConfig(operations.NewGetConfigParams().
				WithTimeout(requestTimeout))
			if err != nil {
				fmt.Printf("failed to create new request: %s\n", err)
				return
			}

			keys, ok := config.Payload.Key.([]interface{})
			if !ok {
				fmt.Printf("key is not array\n")
				return
			}

			keyBytes, err := json.Marshal(keys[0])
			if err != nil {
				fmt.Printf("failed to marshal key: %s\n", err)
				return
			}

			jwk := jose.JSONWebKey{}
			if errUnmarshalJSON := jwk.UnmarshalJSON(keyBytes); errUnmarshalJSON != nil {
				fmt.Printf("failed to unmarshal resp to jwk: %s\n", errUnmarshalJSON)
				return
			}

			k, ok := jwk.Key.(ed25519.PrivateKey)
			if !ok {
				fmt.Printf("key is not ed25519\n")
				return
			}

			bytes, err := json.Marshal(configOutput{DID: *config.Payload.Did, PrivateKey: base58.Encode(k),
				KeyID: fmt.Sprintf("%s#%s", *config.Payload.Did, jwk.KeyID)})
			if err != nil {
				fmt.Printf("failed to marshal: %s\n", err)
				return
			}

			fmt.Println(string(bytes))
		}
	}
}
