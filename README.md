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
- [Hyperledger Aries](https://www.hyperledger.org/use/aries)
- [DIF Sidetree](https://identity.foundation/sidetree/spec/)
- [DID Orb Method](https://trustbloc.github.io/did-method-orb/) 

## Projects
Follow this [link](docs/projects/README.md) to learn more about all the TrustBloc projects and APIs. 

## Sample Applications
- [Issuer](docs/issuer/README.md)
- [Relying Party/Verifier](docs/rp/README.md)
- [Anonymous Comparator and Extractor - Relying Party (ACE-RP)](docs/ace-rp/README.md)

## Demo
- [TrustBloc OpenID for Verifiable Credentials (OpenID4VC)](docs/demo/background-check-usecase.md)
- [TrustBloc VCS](docs/demo/sandbox_vcs_playground.md) : CHAPI + VC Services + Selective Disclosure
  - [Flight Boarding use case](docs/demo/flight-boarding-usecase.md)
- [TrustBloc Adapter](docs/demo/sandbox_adapter_playground.md) : [CHAPI](https://w3c-ccg.github.io/credential-handler-api/)/[WACI-PEx](https://identity.foundation/waci-presentation-exchange/) + DIDComm
  - [Duty Free Shopping use case](docs/demo/duty-free-shop-usecase.md) (WACI-PEx (Issuance + Share) + DIDComm V2)
  - [New Bank Account use case](docs/demo/new-bank-account-usecase.md) (CHAPI + DIDComm V1)
- [TrustBloc Anonymous Comparator and Extractor(ACE)](docs/demo/sandbox_ace_playground.md)

## Components
- [TrustBloc VCS](docs/components/vcs_components.md)
- [TrustBloc Adapter](docs/components/adapter_components.md)
- [TrustBloc Anonymous Comparator and Extractor(ACE)](docs/components/ace_components.md)

## Build and Deployment
For pre-requisites, please refer [TrustBloc k8s deployments](https://github.com/trustbloc/k8s/blob/main/README.md). 
Also, [refer](./docs/dev_steps.md) for detailed steps to update components in sandbox.

The sandbox k8s is dependent on [TrustBloc k8s](https://github.com/trustbloc/k8s). The TRUSTBLOC_CORE_K8S_COMMIT 
variable in [Makefile](Makefile) points to the TrustBloc k8s deployment version. In case of any code/docker 
image changes to the underlying components, update the variable with [k8s commit id](https://github.com/trustbloc/k8s/commits/main). 
Alternatively, uncomment the [symlink command](./k8s/scripts/core_deployment.sh) to point it to the cloned TrustBloc k8s repo.

Run following target to run the components locally.
```
# builds the sandbox images, creates k8s cluster and deploys the trustbloc components
make build-setup-deploy

# pulls the sandbox images from remote registry, creates k8s cluster and deploys the trustbloc components 
make setup-deploy

# stops the k8s cluster
make minikube-down

# undeploys all the components without bringing down minikube
make undeploy-all

# deploys all the components provided minikube is up
make deploy-all
```

The SSL CA cert located inside `~/.trustbloc-k8s/local/certs/` need to be imported to system cert chain.

Refer [Build and Deployment](./docs/demo/build.md) for more information

## Automated testing
Use following targets to run the automation tests built using [WebDriverIO](https://webdriver.io). To run 
this, [npm](https://www.npmjs.com) need to be installed in the system.

```
# runs tests for configurations in ./test/ui-automation/wdio.conf.js (by default, it runs against local deployment)
make automation-test

# runs tests against locally deployed k8s cluster
make automation-test-local

# runs tests against cloud deployed dev k8s cluster 
make automation-test-dev
```

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
