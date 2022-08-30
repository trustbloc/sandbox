/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vccrypto "github.com/trustbloc/ace/pkg/doc/vc/crypto"
)

// CreateVDR creates vdrapi.Registry used by bdd tests.
func CreateVDR(httpClient *http.Client) (vdrapi.Registry, error) {
	orbVDR, err := orb.New(nil, orb.WithDomain(os.Getenv("ORB_DOMAIN")),
		orb.WithHTTPClient(httpClient),
		orb.WithAuthToken(os.Getenv("ORB_AUTH_TOKEN")),
	)
	if err != nil {
		return nil, err
	}

	return vdrpkg.New(vdrpkg.WithVDR(orbVDR)), nil
}

// ResolveDID waits for the DID to become available for resolution.
func ResolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var docResolution *docdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = vdrRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			time.Sleep(3 * time.Second) //nolint:gomnd

			continue
		}

		// check v1 DID is register
		// v1 will return DID with placeholder keys ID (DID#DID) when not register
		// will not return 404
		if strings.Contains(docResolution.DIDDocument.ID, "did:v1") {
			split := strings.Split(docResolution.DIDDocument.AssertionMethod[0].VerificationMethod.ID, "#")
			if strings.Contains(docResolution.DIDDocument.ID, split[1]) {
				fmt.Printf("v1 did %s not register yet will retry %d of %d\n", did, i, maxRetry)
				time.Sleep(3 * time.Second) //nolint:gomnd

				continue
			}
		}
	}

	return docResolution.DIDDocument, nil
}

func newDIDKeys() (*docdid.Doc, ed25519.PrivateKey, error) {
	didDoc := &docdid.Doc{}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	keyID := uuid.New().String()

	jwk, err := jwksupport.JWKFromKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	vm, err := docdid.NewVerificationMethodFromJWK(didDoc.ID+"#"+keyID, vccrypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, nil, err
	}

	didDoc.Authentication = append(didDoc.Authentication, *docdid.NewReferencedVerification(vm, docdid.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *docdid.NewReferencedVerification(vm, docdid.AssertionMethod))

	return didDoc, privateKey, nil
}

func newKey() (crypto.PublicKey, ed25519.PrivateKey, error) { //nolint: unparam
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	return publicKey, privateKey, err
}

// CreateDIDDoc creates did document in vdrapi.Registry.
func CreateDIDDoc(vdr vdrapi.Registry) (*docdid.Doc, ed25519.PrivateKey, error) {
	// create did
	didDoc, privateKey, err := newDIDKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create public keys : %w", err)
	}

	recoverKey, _, err := newKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create recover key : %w", err)
	}

	updateKey, _, err := newKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update recover key : %w", err)
	}

	docResolution, err := vdr.Create(orb.DIDMethod, didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.AnchorOriginOpt, "https://"+os.Getenv("ORB_DOMAIN")),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DID : %w", err)
	}

	return docResolution.DIDDocument, privateKey, nil
}
