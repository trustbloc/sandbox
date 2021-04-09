/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/btcsuite/btcutil/base58"
	"github.com/square/go-jose/v3"
)

func main() {
	switch os.Args[1] { //nolint: gocritic
	case "getPrivateKey":
		jwk := jose.JSONWebKey{}
		if errUnmarshalJSON := jwk.UnmarshalJSON([]byte(os.Args[2])); errUnmarshalJSON != nil {
			fmt.Printf("failed to unmarshal resp to jwk: %s\n", errUnmarshalJSON)
			return
		}

		k, ok := jwk.Key.(ed25519.PrivateKey)
		if !ok {
			fmt.Printf("key is not ed25519\n")
			return
		}

		fmt.Println(base58.Encode(k))
	}
}
