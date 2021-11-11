# TrustBloc Projects

TrustBloc projects are aimed at establishing common standards and development frameworks for next generation digital identity networks. 
Follow [this](https://trustbloc.readthedocs.io/en/latest/) documentation for more details about the framework.

Several projects exist today with the goal of creating digital identities that would allow everyday users to have self-governance over the storage, distribution and control of their identity. However many of these solutions are only offered partially and may not integrate well with each other.
TrustBloc provides the end-to-end architecture that enables the deployment of a production-ready digital identity platform.

Follow this document to learn about applications, APIs, services that various TrustBloc projects are offering along with details of open source standards they are following.

Notable open standard ecosystem TrustBloc is following are,

- [Decentralized Identity Foundation](https://identity.foundation/)
- [W3C](https://www.w3.org/)
- [Hyperledger Aries RFCs](https://github.com/hyperledger/aries-rfcs)


## Projects
 - [TrustBloc Verifiable Credential Services (VCS)](#trustbloc-verifiable-credential-services-vcs)
 - [TrustBloc Wallet](#trustbloc-wallet)
 - [TrustBloc Orb](#trustbloc-orb)
 - [TrustBloc DIDComm Router](#trustbloc-didcomm-router)
 - [TrustBloc Adapters](#trustbloc-adapters)
 - [TrustBloc EDV](#trustbloc-edv)
 - [TrustBloc KMS](#trustbloc-kms)
 - [TrustBloc Demos](#trustbloc-demos)

### TrustBloc Verifiable Credential Services (VCS)
The VC services are a set of RESTful API definitions conforming with the
[OpenAPI 3.0 Specification](https://swagger.io/specification/) (formerly known
as Swagger) for the roles of Issuer, Verifier, and Holder as described in the
[Verifiable Credential Data Model](https://www.w3.org/TR/vc-data-model/)
specification.  These APIs provide a standard set of interfaces by which
interoperability may be tested and verified by various parties who leverage
Verifiable Credentials (VCs).

Current versions of the APIs are,
* [Issuer](https://w3c-ccg.github.io/vc-api/issuer.html)
* [Holder](https://w3c-ccg.github.io/vc-api/holder.html)
* [Verifier](https://w3c-ccg.github.io/vc-api/verifier.html)


##### Notable Standards Followed:
 * [Verifiable Credentials HTTP API v0.3](https://w3c-ccg.github.io/vc-api/): For various operations like authorizing, issuing, verifying, presenting verifiable credentials.
 * [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/): For all the verifiable credential data model operations.
 * [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
 * [Linked Data Proofs v1.0](https://w3c-ccg.github.io/ld-proofs/): For generating JSON-LD based linked data proofs.
 

Visit the [project repo](https://github.com/trustbloc/edge-service) to learn more about VCS services, API documentation and setup instructions.

### TrustBloc Wallet
TODO

### TrustBloc Orb
Orb is a decentralized identifier (DID) method based on a federated and replicated Verifiable Data Registry (VDR). 
The decentralized network consists of Orb servers that write, monitor, witness, and propagate batches of DID operations. 
The batches form a graph that is propagated and replicated between the servers as content-addressable objects. 
These content-addressable objects can be located via both domain and distributed hash table (DHT) mechanisms. 
Each Orb witness server observes a subset of batches in the graph and includes them in their ledgers (as 
append-only Merkle Tree logs). The servers coordinate by propagating batches of DID operations and by monitoring the 
applicable witness servers' ledgers. The Orb servers form a decentralized network without reliance on a common blockchain 
for coordination.


##### Notable Standards Followed:
* [The did:orb Method v0.2](https://trustbloc.github.io/did-method-orb/): For Orb spec.
* [ActivityPub](https://www.w3.org/TR/activitypub/): The ActivityPub protocol is a decentralized social networking protocol 
  based upon the [ActivityStreams 2.0](https://www.w3.org/TR/activitystreams-core/) data format. 
  It provides a client to server API for creating, updating and deleting content, as well as a federated server to server API for delivering notifications and content.
* [WebFinger](https://www.rfc-editor.org/rfc/rfc7033): This specification defines the WebFinger protocol, which can be used
  to discover information about people or other entities on the
  Internet using standard HTTP methods.  WebFinger discovers
  information for a URI that might not be usable as a locator
  otherwise, such as account or email URIs.
* [Sidetree v1.0.0](https://identity.foundation/sidetree/spec/v1.0.0/): Sidetree is a protocol for creating scalable [Decentralized Identifier](https://w3c.github.io/did-core/) networks that can run 
  atop any existing decentralized anchoring system (e.g. Bitcoin, Ethereum, distributed ledgers, witness-based approaches) and be as open, public, and permissionless as 
  the underlying anchoring systems they utilize. The protocol allows users to create globally unique, user-controlled identifiers and manage 
  their associated PKI metadata, all without the need for centralized authorities or trusted third parties. The syntax of the identifier and accompanying data model used 
  by the protocol is conformant with the [W3C Decentralized Identifiers](https://w3c.github.io/did-core/) specification. Implementations of the protocol can be codified as their own distinct DID Methods and registered 
  in the [W3C DID Method Registry](https://w3c.github.io/did-spec-registries/#did-methods).


Visit the [project repo](https://github.com/trustbloc/orb) to learn more about Orb services, API documentation and setup instructions.

### TrustBloc DIDComm Router
TODO

### TrustBloc Adapters
TODO

### TrustBloc EDV
TODO

### TrustBloc KMS
TODO

### TrustBloc Demos
TODO

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
