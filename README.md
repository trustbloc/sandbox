[![Release](https://img.shields.io/github/release/trustbloc/sandbox.svg?style=flat-square)](https://github.com/trustbloc/sandbox/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/sandbox/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/sandbox)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.sandbox?branchName=main)](https://dev.azure.com/trustbloc/edge/_build/latest?definitionId=27&branchName=main)
[![codecov](https://codecov.io/gh/trustbloc/sandbox/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/sandbox)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/sandbox)](https://goreportcard.com/report/github.com/trustbloc/sandbox)

# sandbox

Sandbox contains the sample implementations of Issuer and Verifier/RP to demonstrate the following main features provided 
by the [TrustBloc](https://github.com/trustbloc) projects.
- [W3C Verifiable Credential(VC)](https://w3c.github.io/vc-data-model/)
- [W3C Decentralized Identifier(DID)](https://w3c.github.io/did-core/)
- [Hyperledger Fabric](https://www.hyperledger.org/use/fabric)
- [Hyperledger Aries](https://www.hyperledger.org/use/aries)
- [DIF Sidetree](https://identity.foundation/sidetree/spec/)
- [TrustBloc DID Method](https://github.com/trustbloc/trustbloc-did-method/blob/main/docs/spec/trustbloc-did-method.md) 

## Build
The sandbox example can be run with the following modes.
- Sidetree with mock ledger
- Sidetree with Hyperledger Fabric

Refer [Build](docs/demo/build.md) for more detailed information.

## Sample Applications
- [Issuer](docs/issuer/README.md)
- [Relying Party/Verifier](docs/rp/README.md)
- [Anonymous Comparator Relying Party (AC-RP)](docs/rp/README.md)

## Demo
- [TrustBloc VCS](docs/demo/sandbox_vcs_playground.md) : CHAPI + VC Services
- [TrustBloc Adapter](docs/demo/sandbox_adapter_playground.md) : CHAPI + DIDComm
  - [New Bank Account use case](docs/demo/new-bank-account-usecase.md)
  - [Register property use case](docs/demo/register-property-usecase.md)

## Components
- [TrustBloc VCS](docs/components/vcs_components.md)
- [TrustBloc Adapter](docs/components/adapter_components.md)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
