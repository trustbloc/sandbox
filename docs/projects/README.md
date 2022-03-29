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
- [OpenID](https://openid.net)
- [IETF](https://www.ietf.org/)


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
 * [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/): For signing and verifying verifiable credentials and presentations.
 

Visit the [project repo](https://github.com/trustbloc/vcs) to learn more about VCS services, API documentation, configuration and setup instructions.

### TrustBloc Wallet
The TrustBloc Wallet is [Universal Wallet](https://w3c-ccg.github.io/universal-wallet-interop-spec/) based [Verifiable Credential](https://www.w3.org/TR/vc-data-model/) 
digital Web Wallet implementation for storing and sharing Verifiable Credentials, also with support for [DIDComm](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0005-didcomm/README.md).

This Project has 2 components,
- Wallet Web: Browser based client-side component of web wallet.
- Wallet Server: Server component of web wallet, which provides features like user on-boarding, user management etc.

Useful documents to learn more about TrustBloc Wallets
* [User Agent Web Wallet](https://github.com/trustbloc/wallet/blob/main/docs/components/wallet_web.md)
* [Aries Verifiable Credential Wallet](https://github.com/hyperledger/aries-framework-go/blob/main/docs/vc_wallet.md)
* [Wallet JavaScript SDK](https://github.com/trustbloc/agent-sdk/blob/main/cmd/wallet-js-sdk/docs/wallet_sdk.md)


##### Notable Standards Followed:
 * [Universal Wallet 2020](https://w3c-ccg.github.io/universal-wallet-interop-spec/): All wallet operations are based on the universal wallet standard interfaces and data models, 
 like credential operations, managing decentralized identifiers, user preferences etc.
 * [WACI Presentation Exchange](https://identity.foundation/waci-presentation-exchange/): Wallet and credential interaction standards using DIDComm.
 * [Credential Handler API v1.0](https://w3c-ccg.github.io/credential-handler-api/): This specification defines capabilities that enable third-party Web applications to handle credential requests and storage.
  This is used for implementing browser based polyfill web wallets.
 * [Verifiable Presentation Request Specification v0.1](https://w3c-ccg.github.io/vp-request-spec/): Standards for requesting credentials to share from wallet.
 * [Presentation Exchange v2.0.0](https://identity.foundation/presentation-exchange/): An advanced form credential request standard which codifies a data format Verifiers can use to articulate proof requirements, and a data format Holders can use to describe proofs submitted in accordance with them.
 * [Confidential Storage v0.1](https://identity.foundation/confidential-storage/): For secured storage of wallet contents, also know as Encrypted Data Vault.
 * [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/): For all the verifiable credential data model operations.
 * [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
 * [Linked Data Proofs v1.0](https://w3c-ccg.github.io/ld-proofs/): For generating JSON-LD based linked data proofs.
 * [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/): For signing and verifying verifiable credentials and presentations.
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
 * [Authorization Capabilities for Linked Data v0.3](https://w3c-ccg.github.io/zcap-ld/): Followed for implementing advanced wallet features which provides a secure way for linked data systems to grant and express authority utilizing the object capability model.
 * [Decentralized Identifier Resolution (DID Resolution) v0.2](https://w3c-ccg.github.io/did-resolution/): Followed for resolving various decentralized identifiers. 
 * [The did:orb Method v0.2](https://trustbloc.github.io/did-method-orb/): For Orb decentralized identifiers which is the default decentralized idenitfiers for TrustBloc wallets.
 * [Aries RFCS](#aries-rfcs): Since TrustBloc wallet is built on aries framework based user agents, it follows many aries RFCs features like DIDComm, Out-Of-Band Messaging, Issue Credential Protocol, Present Proof Protocol, Messaging, Mediators etc.
 * [DIDComm V2](https://identity.foundation/didcomm-messaging/spec/): Version 2 of DID Communication protocol for secured communication between wallet and issuer/relying party.
 * [Credential Manifest](https://identity.foundation/credential-manifest/): Credential Manifests are a resource format that defines preconditional requirements, Issuer style preferences, Credential Style preferences and other facets User Agents utilize to help articulate and select the inputs necessary for processing and issuance of a specified credential.

Currently In Progress
* [OIDC for Verifiable Presentation](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html): extension of OpenID Connect to allow presentation of claims in the form of W3C Verifiable Credentials as part of the protocol flow in addition to claims provided in the id_token and/or via UserInfo responses
* [OIDC for Verifiable Credential Issuance](https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0.html): Extension of OpenID Connect to allow holders to request issuance of verifiable credentials
* [Grant Negotiation and Authorization Protocol](https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html): This protocol allows a wallet instance to request delegated authorization to resource servers and to request direct information.
    
Visit the [project repo](https://github.com/trustbloc/wallet) to learn more about web wallet, API documentation, configuration and setup instructions.


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
* [Activity Anchors v0.1](https://trustbloc.github.io/activityanchors/): The decentralized network consists of Activity Anchor Servers that write, monitor, witness, and propagate batches of document operations. TrustBloc Orb 
has implemented data model and rules for representing a graph of batches by following this standard.


Visit the [project repo](https://github.com/trustbloc/orb) to learn more about Orb services, API documentation, configuration and setup instructions.

### TrustBloc DIDComm Router
The TrustBloc hub-router is a working implementation of the [Mediator Coordination](https://github.com/hyperledger/aries-rfcs/blob/main/features/0211-route-coordination/README.md) and 
the [Pickup](https://github.com/hyperledger/aries-rfcs/blob/main/features/0212-pickup/README.md) protocols built using [Hyperledger Aries Framework](https://github.com/hyperledger/aries-framework-go).
This hub-router can be used by edge agents like web wallet or mobile wallets to send/receive DIDComm messages on their behalf.

##### Notable Standards Followed:
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the router.
 * [Aries RFCS](#aries-rfcs): The router implements many aries RFCs for receving and sending messages secureley on behalf of registered edge agents.
    * [Mediator Coordination](https://github.com/hyperledger/aries-rfcs/blob/main/features/0211-route-coordination/README.md)
    * [Pickup](https://github.com/hyperledger/aries-rfcs/blob/main/features/0212-pickup/README.md) 
    * [DIDComm Between Two Mobile Agents Using Cloud Agent Mediator](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0346-didcomm-between-two-mobile-agents/README.md) 
 * [DIDComm V2](https://identity.foundation/didcomm-messaging/spec/): Version 2 of DID Communication protocol for secured communication between wallet and issuer/relying party.

Visit the [project repo](https://github.com/trustbloc/hub-router) to learn more about hub-router, API documentation, configuration and setup instructions.

### TrustBloc Adapters
The TrustBloc Adapter acts as an intermediary between Relying Party/Issuer components to support DIDComm operations by hiding majority of the complex interactions or operations. 
The adapter uses the capabilities provided by [Hyperledger Aries Framework](https://github.com/hyperledger/aries-framework-go) such as DIDComm, W3C Verifiable Credentials(VC), W3C Decentralized Identifiers(DIDs), etc.

The Adapter contains following components.

* [Issuer Adapter](https://github.com/trustbloc/adapter/blob/main/docs/issuer/README.md) :
* [Relying Party (RP) Adapter](https://github.com/trustbloc/adapter/blob/main/docs/rp/README.md)

The TrustBloc Adapters also provides support for DIDComm to go through a router using [Blinded Routing feature](https://github.com/trustbloc/adapter/blob/main/docs/blinded_routing.md).

##### Notable Standards Followed:
 * [Verifiable Presentation Request Specification v0.1](https://w3c-ccg.github.io/vp-request-spec/): Standards for requesting credentials to share from user's wallet.
 * [Presentation Exchange v2.0.0](https://identity.foundation/presentation-exchange/): An advanced form credential request standard which codifies a data format Verifiers can use to articulate proof requirements, and a data format Holders can use to describe proofs submitted in accordance with them.
 * [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/): For all the verifiable credential data model operations.
 * [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
 * [Linked Data Proofs v1.0](https://w3c-ccg.github.io/ld-proofs/): For generating JSON-LD based linked data proofs.
 * [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/): For signing and verifying verifiable credentials and presentations.
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
 * [Authorization Capabilities for Linked Data v0.3](https://w3c-ccg.github.io/zcap-ld/): Followed for implementing features which provides a secure way for linked data systems to grant and express authority utilizing the object capability model.
 * [Decentralized Identifier Resolution (DID Resolution) v0.2](https://w3c-ccg.github.io/did-resolution/): Followed for resolving various decentralized identifiers. 
 * [The did:orb Method v0.2](https://trustbloc.github.io/did-method-orb/): For Orb decentralized identifiers which is the default decentralized idenitfiers for TrustBloc wallets.
 * [Aries RFCS](#aries-rfcs): Since TrustBloc adapters performs credential interaction using aries based framework, it follows many aries RFCs standards for DIDComm, Out-Of-Band Messaging, Issue Credential Protocol, Present Proof Protocol, Messaging etc.
 * [DIDComm V2](https://identity.foundation/didcomm-messaging/spec/): Version 2 of DID Communication protocol for secured communication between wallet and issuer/relying party.
 * [Credential Manifest](https://identity.foundation/credential-manifest/): Credential Manifests are a resource format that defines preconditional requirements, Issuer style preferences, Credential Style preferences and other facets User Agents utilize to help articulate and select the inputs necessary for processing and issuance of a specified credential.
 * [WACI Presentation Exchange](https://identity.foundation/waci-presentation-exchange/): Wallet and credential interaction standards using DIDComm.

Visit the [project repo](https://github.com/trustbloc/adapter) to learn more about adapters, API documentation, configuration and setup instructions.

### TrustBloc EDV
An implementation of Encrypted Data Vaults from the [Confidential Storage v0.1](https://identity.foundation/confidential-storage/) specification. 
This encrypted data vault is used by various TrustBloc components to save user data, like wallet contents of wallet user.

##### Notable Standards Followed:
 * [Confidential Storage v0.1](https://identity.foundation/confidential-storage/): For secured storage of wallet contents, also know as Encrypted Data Vault.
 * [JSON-LD v1.1](https://w3c.github.io/json-ld-syntax/): For JSON-based Serialization for Linked Data.
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
 * [Authorization Capabilities for Linked Data v0.3](https://w3c-ccg.github.io/zcap-ld/): Followed for implementing advanced wallet features which provides a secure way for linked data systems to grant and express authority utilizing the object capability model.
 * [Aries RFCS](#aries-rfcs): Since TrustBloc EDV uses on aries framework based storage interfaces, it follows many aries RFCs features related to secured data storage.

Visit the [project repo](https://github.com/trustbloc/edv) to learn more about edv, API documentation, configuration and setup instructions.


### TrustBloc KMS
The TrustBloc KMS is an implementation of the remote Key Management System. It exposes kms/crypto operations over REST API.
Refer [design overview](https://github.com/trustbloc/kms/blob/main/docs/design_overview.md) of TrustBloc KMS for more details.

##### Notable Standards Followed:
 * [Confidential Storage v0.1](https://identity.foundation/confidential-storage/): For secured storage of wallet contents, also know as Encrypted Data Vault.
 * [WebKMS v0.7](https://w3c-ccg.github.io/webkms/): For implementing cryptographic key management systems for the wallet.
 * [Authorization Capabilities for Linked Data v0.3](https://w3c-ccg.github.io/zcap-ld/): Followed for implementing advanced wallet features which provides a secure way for linked data systems to grant and express authority utilizing the object capability model.
 * [Aries RFCS](#aries-rfcs): Since TrustBloc KMS follows many aries RFCs standards related to key management.

Currently In Progress
 * [Grant Negotiation and Authorization Protocol](https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html): This protocol allows a client instance to request delegated authorization to resource servers and to request direct information.

Visit the [project repo](https://github.com/trustbloc/kms) to learn more about TrustBloc KMS, API documentation, configuration and setup instructions.

### TrustBloc Demos
The TrustBloc Demo is decentralized identity ecosystem sample application built using all of the above TrustBloc components to demonstrate their interactions by following various open standards.

### Sample Applications
- [Issuer](../issuer/README.md)
- [Relying Party/Verifier](../rp/README.md)
- [Anonymous Comparator and Extractor - Relying Party (ACE-RP)](../ace-rp/README.md)

### Demos
- [TrustBloc VCS](../demo/sandbox_vcs_playground.md) : CHAPI + VC Services + Selective Disclosure
  - [Flight Boarding use case](../demo/flight-boarding-usecase.md)
- [TrustBloc Adapter](../demo/sandbox_adapter_playground.md) : [CHAPI](https://w3c-ccg.github.io/credential-handler-api/)/[WACI-PEx](https://identity.foundation/waci-presentation-exchange/) + DIDComm
  - [Duty Free Shopping use case](../demo/duty-free-shop-usecase.md) (WACI-PEx + DIDComm)
  - [New Bank Account use case](../demo/new-bank-account-usecase.md) (CHAPI + DIDComm)
- [TrustBloc Anonymous Comparator and Extractor(ACE)](../demo/sandbox_ace_playground.md)

### Component Details
- [TrustBloc VCS](../components/vcs_components.md)
- [TrustBloc Adapter](../components/adapter_components.md)
- [TrustBloc Anonymous Comparator and Extractor(ACE)](../components/ace_components.md) 

Visit the [project repo](https://github.com/trustbloc/sandbox) to learn more about TrustBloc Demos.


## Aries RFCs

Most of the TrustBloc projects are based Aries Framework which has implemented below [aries RFCS](https://github.com/hyperledger/aries-rfcs) mentioned. 
* 0003: Protocols
* 0004: Agents
* 0005: DID Communication
* 0008: Message ID and Threading
* 0011: Decorators
* 0015: ACKs
* 0017: Attachments
* 0019: Encryption Envelope
* 0020: Message Types
* 0023: DID Exchange Protocol 1.0
* 0025: DIDComm Transports
* 0035: Report Problem Protocol 1.0
* 0036: Issue Credential Protocol 1.0
* 0037: Present Proof Protocol 1.0
* 0044: DIDComm File and MIME Types
* 0046: Mediators and Relays
* 0047: JSON-LD Compatibility
* 0092: Transports Return Route
* 0160: Connection Protocol
* 0211: Mediator Coordination Protocol
* 0302: Aries Interop Profile
* 0360: did:key Usage
* 0434: Out-of-Band Protocol 1.1
* 0441: Prover and Verifier Best Practices for Proof Presentation
* 0453: Issue Credential Protocol 2.0
* 0454: Present Proof Protocol 2.0
* 0510: Presentation-Exchange Attachment format for requesting and presenting proofs
* 0519: Goal Codes
* 0557: Discover Features Protocol v2.x
* 0587: Encryption Envelope v2
* 0593: JSON-LD Credential Attachment format for requesting and issuing credentials
* 0627: Static Peer DIDs
* 0646: W3C Credential Exchange using BBS+ Signatures
* 0348: Transition Message Type to HTTPs
* 0021: DIDComm Message Anatomy
* 0024: DIDComm over XMPP
* 0028: Introduce Protocol 1.0
* 0056: Service Decorator
* 0067: DIDComm DID document conventions
* 0074: DIDComm Best Practices
* 0124: DID Resolution Protocol 0.9
* 0270: Interop Test Suite
* 0309: DIDAuthZ
* 0317: Please ACK Decorator
* 0335: HTTP Over DIDComm
* 0346: DIDComm Between Two Mobile Agents Using Cloud Agent Mediator
* 0351: Purpose Decorator
* 0511: Credential-Manifest Attachment format for requesting and presenting credentials
* 0700: Out-of-Band through redirect

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
