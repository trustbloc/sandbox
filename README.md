[![Release](https://img.shields.io/github/release/trustbloc/edge-sandbox.svg?style=flat-square)](https://github.com/trustbloc/edge-sandbox/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-sandbox/master/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edge-sandbox)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.edge-sandbox?branchName=master)](https://dev.azure.com/trustbloc/edge/_build/latest?definitionId=27&branchName=master)
[![codecov](https://codecov.io/gh/trustbloc/edge-sandbox/branch/master/graph/badge.svg)](https://codecov.io/gh/trustbloc/edge-sandbox)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edge-sandbox)](https://goreportcard.com/report/github.com/trustbloc/edge-sandbox)

# edge-sandbox

Edge Sandbox contains the sample implementations of Issuer and Verifier/RP to demonstrate the following main features provided 
by the [TrustBloc](https://github.com/trustbloc) projects.
- [W3C Verifiable Credential(VC)](https://w3c.github.io/vc-data-model/)
- [W3C Decentralized Identifier(DID)](https://w3c.github.io/did-core/)
- [Hyperledger Fabric](https://www.hyperledger.org/use/fabric)
- [Hyperledger Aries](https://www.hyperledger.org/use/aries)
- [DIF Sidetree](https://identity.foundation/sidetree/spec/)
- [TrustBloc DID Method](https://github.com/trustbloc/trustbloc-did-method/blob/master/docs/spec/trustbloc-did-method.md) 

## Build
The sandbox example can be run with the following modes.
- Sidetree with mock ledger
- Sidetree with Hyperledger Fabric

Refer [Build](docs/demo/build.md) for more detailed information.

## Sample Applications
- [Issuer](docs/issuer/README.md)
- [Relying Party](docs/rp/README.md)

## Demo
- [Non DIDComm](docs/demo/sandbox_nondidcomm_playground.md)
- [DIDComm](docs/demo/sandbox_didcomm_playground.md)

## Component Diagram
- [Non DIDComm](docs/demo/nondidcomm_component_diagram.svg)
- [DIDComm](docs/demo/didcomm_component_diagram.svg)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
