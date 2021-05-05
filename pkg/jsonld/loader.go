/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	_ "embed" //nolint:gci // required for go:embed
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

// nolint:gochecknoglobals // required for go:embed
var (
	//go:embed contexts/w3id-citizenship-v1.jsonld
	w3idCitizenshipV1 []byte
	//go:embed contexts/w3id-vaccination-v1.jsonld
	w3idVaccinationV1 []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtV1 []byte
	//go:embed contexts/booking-reference-v1.jsonld
	bookingRefV1 []byte
)

var embedContexts = []jsonld.ContextDocument{ //nolint:gochecknoglobals
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     w3idCitizenshipV1,
	},
	{
		URL:         "https://w3id.org/vaccination/v1",
		DocumentURL: "https://w3c-ccg.github.io/vaccination-vocab/context/v1/index.json",
		Content:     w3idVaccinationV1,
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		DocumentURL: "",
		Content:     examplesExtV1,
	},
	{
		URL:         "https://trustbloc.github.io/context/vc/examples/booking-ref-v1.jsonld",
		DocumentURL: "",
		Content:     bookingRefV1,
	},
}

// DocumentLoader returns a JSON-LD document loader with preloaded contexts.
func DocumentLoader(storageProvider storage.Provider) (ld.DocumentLoader, error) {
	loader, err := jsonld.NewDocumentLoader(storageProvider, jsonld.WithExtraContexts(embedContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
