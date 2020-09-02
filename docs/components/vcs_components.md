# TrustBloc VCS Components

## Architecture Diagram
![VCS Architecture diagram](../images/vcs_component_diagram.svg)

## Component Details
### Core
| Component            | Source URL                                                                   | Sample Docker Configuration                                                                                                         |
|----------------------|------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| EDV                  | [Source](https://github.com/trustbloc/edv)                                   | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L164-L177) |
| DID Resolver         | [Source](https://github.com/trustbloc/edge-service/tree/master/cmd/did-rest) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L146-L162) |
| TrustBloc DID Method | [Source](https://github.com/trustbloc/trustbloc-did-method)                  | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L198-L212) |
| Sidetree Fabric      | [Source](https://github.com/trustbloc/sidetree-fabric)                       | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-sidetree-fabric.yml)           |

### Wallet
| Component  | Source URL                                        | Sample Docker Configuration                                                                                                         |
|------------|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| User Agent | [Source](https://github.com/trustbloc/edge-agent) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L179-L196) |

### Services
| Component           | Source URL                                          | Sample Docker Configuration                                                                                                       |
|---------------------|-----------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Issuer VC Service   | [Source](https://github.com/trustbloc/edge-service) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L11-L42) |
| Verifier VC Service | [Source](https://github.com/trustbloc/edge-service) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-edge-components.yml#L44-L75) |

### Demo
| Component         | Source URL                                          | Sample Docker Configuration                                                                                                         |
|-------------------|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| Issuer            | [Source](https://github.com/trustbloc/edge-sandbox) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-demo-applications.yml#L11-L43) |
| RP/Verifier       | [Source](https://github.com/trustbloc/edge-sandbox) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-demo-applications.yml#L45-L69) |
| ORY Hydra         | [Source](https://github.com/ory/hydra)              | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-third-party.yml#L11-L40)       |
| Login and Consent | [Source](https://github.com/trustbloc/edge-sandbox) | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-third-party.yml#L157-L171)     |
| ORY Oathkeeper    | [Source](https://github.com/ory/oathkeeper)         | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-third-party.yml#L42-L63)       |
| Strapi            | [Source](https://github.com/strapi/strapi)          | [Docker](https://github.com/trustbloc/edge-sandbox/blob/v0.1.4/test/bdd/fixtures/demo/docker-compose-third-party.yml#L65-L86)       |
