# TrustBloc Anonymous Comparator and Extractor(ACE) Components

## v0.1.6
### Architecture Diagram 
![Anonymous Comparator and Extractor(ACE) Architecture diagram v0.1.6](../images/ace_component_diagram_v0.1.6.svg)

### Component Details
### Core
| Component                      | Source URL                                                                                 | Sample Docker Configuration                                                                                          |
|--------------------------------|--------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| EDV                            | [Source](https://github.com/trustbloc/edv)                                                 | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-edv.yml)             |
| KMS                            | [Source](https://github.com/trustbloc/hub-kms)                                             | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-kms.yml)             |
| Confidential Storage Hub (CSH) | [Source](https://github.com/trustbloc/edge-service/tree/main/cmd/confidential-storage-hub) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-csh.yml)             |
| DID Resolver                   | [Source](https://github.com/trustbloc/edge-service/tree/main/cmd/did-rest)                 | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-resolver.yml)        |
| TrustBloc DID Method           | [Source](https://github.com/trustbloc/trustbloc-did-method)                                | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-did-method.yml)      |
| Sidetree Fabric                | [Source](https://github.com/trustbloc/sidetree-fabric)                                     | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-sidetree-fabric.yml) |

### Services
| Component         | Source URL                                                                        | Sample Docker Configuration                                                                                     |
|-------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Vault             | [Source](https://github.com/trustbloc/edge-service/tree/main/cmd/vault-server)    | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-vault.yml)      |
| Comparator        | [Source](https://github.com/trustbloc/edge-service/tree/main/cmd/comparator-rest) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-comparator.yml) |
| Issuer VC Service | [Source](https://github.com/trustbloc/edge-service)                               | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-vcs.yml)        |

### Demo
| Component                                    | Source URL                                                               | Sample Docker Configuration                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| Sample Application RPs (UCIS, CBP, Benefits) | [Source](https://github.com/trustbloc/sandbox/tree/main/cmd/ace-rp-rest) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-demo-applications.yml) |

