package operation

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"time"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vccrypto "github.com/trustbloc/ace/pkg/doc/vc/crypto"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
)

func (c *Operation) createLongVDR() (*ariesdid.DocResolution, *ed25519.PrivateKey, error) { //nolint:funlen
	vdr, err := longform.New()
	if err != nil {
		return nil, nil, err
	}

	recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	didPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	jwk, err := jwksupport.JWKFromKey(didPublicKey)
	if err != nil {
		return nil, nil, err
	}

	vm, err := ariesdid.NewVerificationMethodFromJWK("key1", "Ed25519VerificationKey2018", "", jwk)
	if err != nil {
		return nil, nil, err
	}

	didDoc := &ariesdid.Doc{}

	// add did keys
	didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

	// add did services
	didDoc.Service = []ariesdid.Service{
		{
			ID:   "svc1",
			Type: "type",
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{
					URI:         "http://example.com",
					RoutingKeys: []string{"key1"},
				},
			}),
		},
	}

	// create did
	createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(longform.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(longform.UpdatePublicKeyOpt, updateKey),
	)

	if err != nil {
		return nil, nil, err
	}

	return createdDocResolution, &updateKeyPrivateKey, nil
}

func (c *Operation) createDidVDR(httpClient *http.Client) (*ariesdid.DocResolution, *ed25519.PrivateKey, error) {
	token := os.Getenv("ORB_AUTH_TOKEN")
	orbVDR, err := orb.New(nil,
		orb.WithDomain(os.Getenv("ORB_DOMAIN")),
		orb.WithHTTPClient(httpClient),
		orb.WithAuthToken(token),
	)

	if err != nil {
		return nil, nil, err
	}

	vdr := vdrpkg.New(vdrpkg.WithVDR(orbVDR))

	didDoc, privateKey, err := c.newDIDKeys()
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

	return docResolution, &privateKey, nil
}

func (c *Operation) newDIDKeys() (*docdid.Doc, ed25519.PrivateKey, error) {
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

func (c *Operation) createProof(
	privateKey ed25519.PrivateKey,
	verificationKID string,
	cNonce string,
	oauthClientID string,
) (string, error) {
	jwtSigner := jwt.NewEd25519Signer(privateKey)

	claims := &jwtProofClaims{
		Issuer:   oauthClientID,
		IssuedAt: time.Now().Unix(),
		Nonce:    cNonce,
	}

	jwtHeaders := map[string]interface{}{
		"alg": "EdDSA",
		"kid": verificationKID,
	}

	signedJWT, err := jwt.NewSigned(claims, jwtHeaders, jwtSigner)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed jwt: %w", err)
	}

	return jws, nil
}
