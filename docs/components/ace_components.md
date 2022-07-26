# TrustBloc Anonymous Comparator and Extractor(ACE) Components

## v0.1.8
### Architecture Diagram 
![Anonymous Comparator and Extractor(ACE) Architecture diagram v0.1.8](../images/ace_component_diagram_v0.1.8.svg)

[DID Orb Component Diagram](https://trustbloc.readthedocs.io/en/latest/orb/introduction.html)

### Component Details
#### Core
| Component                      | Source URL                                                                        | k8s Configuration                                            |
|--------------------------------|-----------------------------------------------------------------------------------|--------------------------------------------------------------|
| EDV                            | [Source](https://github.com/trustbloc/edv)                                        | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/edv)      |
| KMS                            | [Source](https://github.com/trustbloc/kms)                                        | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/kms)      |
| Confidential Storage Hub (CSH) | [Source](https://github.com/trustbloc/ace/tree/main/cmd/confidential-storage-hub) | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/csh)      |
| DID Resolver                   | [Source](https://github.com/trustbloc/did-resolver/tree/main/cmd/did-rest)        | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/resolver) |
| DID Orb                        | [Source](https://github.com/trustbloc/orb)                                        | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/orb)      |

#### Services
| Component  | Source URL                                                               | k8s Configuration                                                      |
|------------|--------------------------------------------------------------------------|------------------------------------------------------------------------|
| Vault      | [Source](https://github.com/trustbloc/ace/tree/main/cmd/vault-server)    | [k8s](https://github.com/trustbloc/k8s/tree/v0.1.8/vault-server)       |
| Comparator | [Source](https://github.com/trustbloc/ace/tree/main/cmd/comparator-rest) | [k8s](https://github.com/trustbloc/sandbox/tree/v0.1.8/k8s/comparator) |


#### Demo
| Component                                    | Source URL                                                               | k8s Configuration                                                  |
|----------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------|
| Sample Application RPs (UCIS, CBP, Benefits) | [Source](https://github.com/trustbloc/sandbox/tree/main/cmd/ace-rp-rest) | [k8s](https://github.com/trustbloc/sandbox/tree/v0.1.8/k8s/ace-rp) |


## v0.1.7
### Architecture Diagram 
![Anonymous Comparator and Extractor(ACE) Architecture diagram v0.1.7](../images/ace_component_diagram_v0.1.7.svg)

TODO : Add link to DID Orb Component Diagram

### Component Details
#### Core
| Component                      | Source URL                                                                        | k8s Configuration                                                                              |
|--------------------------------|-----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| EDV                            | [Source](https://github.com/trustbloc/edv)                                        | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/edv)      |
| KMS                            | [Source](https://github.com/trustbloc/kms)                                        | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/kms)      |
| Confidential Storage Hub (CSH) | [Source](https://github.com/trustbloc/ace/tree/main/cmd/confidential-storage-hub) | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/csh)      |
| DID Resolver                   | [Source](https://github.com/trustbloc/did-resolver/tree/main/cmd/did-rest)        | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/resolver) |
| DID Orb                        | [Source](https://github.com/trustbloc/orb)                                        | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/orb)      |

#### Services
| Component         | Source URL                                                               | k8s Configuration                                                                                        |
|-------------------|--------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Vault             | [Source](https://github.com/trustbloc/ace/tree/main/cmd/vault-server)    | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/vault-server)       |
| Comparator        | [Source](https://github.com/trustbloc/ace/tree/main/cmd/comparator-rest) | [k8s](https://github.com/trustbloc/sandbox/tree/59b6dee1552f7afdea3a8b6f804e3dfdfcc0837e/k8s/comparator) |
| Issuer VC Service | [Source](https://github.com/trustbloc/vcs)                               | [k8s](https://github.com/trustbloc/k8s/tree/b7254443d1efdbb7f7819aeeffff687a38f40706/vcs)                |

#### Demo
| Component                                    | Source URL                                                               | k8s Configuration                                                                                    |
|----------------------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Sample Application RPs (UCIS, CBP, Benefits) | [Source](https://github.com/trustbloc/sandbox/tree/main/cmd/ace-rp-rest) | [k8s](https://github.com/trustbloc/sandbox/tree/59b6dee1552f7afdea3a8b6f804e3dfdfcc0837e/k8s/ace-rp) |



## v0.1.6
### Architecture Diagram 
![Anonymous Comparator and Extractor(ACE) Architecture diagram v0.1.6](../images/ace_component_diagram_v0.1.6.svg)

### Component Details
#### Core
| Component                      | Source URL                                                                        | Sample Docker Configuration                                                                                          |
|--------------------------------|-----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| EDV                            | [Source](https://github.com/trustbloc/edv)                                        | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-edv.yml)             |
| KMS                            | [Source](https://github.com/trustbloc/kms)                                        | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-kms.yml)             |
| Confidential Storage Hub (CSH) | [Source](https://github.com/trustbloc/ace/tree/main/cmd/confidential-storage-hub) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-csh.yml)             |
| DID Resolver                   | [Source](https://github.com/trustbloc/did-resolver/tree/main/cmd/did-rest)        | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-resolver.yml)        |
| TrustBloc DID Method           | [Source](https://github.com/trustbloc/trustbloc-did-method)                       | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-did-method.yml)      |
| Sidetree Fabric                | [Source](https://github.com/trustbloc/sidetree-fabric)                            | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-sidetree-fabric.yml) |

#### Services
| Component         | Source URL                                                               | Sample Docker Configuration                                                                                     |
|-------------------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Vault             | [Source](https://github.com/trustbloc/ace/tree/main/cmd/vault-server)    | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-vault.yml)      |
| Comparator        | [Source](https://github.com/trustbloc/ace/tree/main/cmd/comparator-rest) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-comparator.yml) |
| Issuer VC Service | [Source](https://github.com/trustbloc/vcs)                               | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-vcs.yml)        |

#### Demo
| Component                                    | Source URL                                                               | Sample Docker Configuration                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| Sample Application RPs (UCIS, CBP, Benefits) | [Source](https://github.com/trustbloc/sandbox/tree/main/cmd/ace-rp-rest) | [Docker](https://github.com/trustbloc/sandbox/blob/v0.1.6/test/bdd/fixtures/demo/docker-compose-demo-applications.yml) |

