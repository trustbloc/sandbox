# Register Property Use Case

**Use Case**: As a user, I should be able to register my property online by providing my digital 
drivers license, digital drivers license assurance/evidence and digital credit report.

## References
- [Demo Recording](https://www.youtube.com/watch?v=0ZNmk6E2EFE&feature=youtu.be)
- [Component Diagram](../images/adapter_component_diagram.svg)
- [Issuer Adapter](https://github.com/trustbloc/edge-adapter/blob/master/docs/issuer/README.md)
- [RP Adapter](https://github.com/trustbloc/edge-adapter/blob/master/docs/rp/README.md)

## Components

| Component                          | Cloud URL (Sandbox)                                                          | Cloud URL (Dev)                                                    | Local URL*                                                        |
|------------------------------------|------------------------------------------------------------------------------|--------------------------------------------------------------------|-------------------------------------------------------------------|
| User Wallet                        |                                                                              |                                                                    | [Click Here](https://myagent.trustbloc.local/dashboard)    |
| Government of Utopia               |                                                                              |                                                                    | [Click Here](https://rp.trustbloc.local/government)               |
| Drivers License + Assurance Issuer |                                                                              |                                                                    | [Click Here](https://issuer.trustbloc.local/uploaddrivinglicense) |
| Credit Report Issuer               |                                                                              |                                                                    | [Click Here](https://issuer.trustbloc.local/creditscorenologin)   |

*: Refer [here](./build.md) to run the demo locally.

## Flow details
1. Login to Wallet:
   - UI Navigation 
     - Go to [`Wallet`](#components) and click on Login button with default user name and password.
   - Details 
     - A new [DID]((https://w3c.github.io/did-core/)) (identity) gets created for the user.
     - The `Wallet` registers with the [DIDComm Mediator/Router](https://github.com/hyperledger/aries-framework-go/blob/master/docs/didcomm_mediator.md).
1. Get Drivers License and Connect to Assurance Issuer: 
   - UI Navigation 
     - On [`Drivers License + Assurance Issuer`](#components) page, click on `Upload Driving Licence` button. 
     - Scan your Driving Licence and click `agree` on the consent page.
     - Click `Next` on the window, select the `wallet` and click `Store and Connect`.    
   - Details 
     - The Issuer Adapter provides following details to wallet through [CHAPI](https://w3c-ccg.github.io/credential-handler-api/).
         - Drivers License
         - DIDComm Invitation to connect to issuer adapter
         - Manifest Credential with details about Assurance Issuer
     - The Wallet performs [Aries DID Exchange protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange) with the Issuer Adapter
     - The Wallet responds with success message through CHAPI.
1. Verify Drivers License in the Wallet:
   - UI Navigation 
     - Go to [`Wallet`](#components) and confirm the data in `Drivers License` under stored credentials. 
1. Connect to Credit Report Issuer:
   - UI Navigation 
      - Browse to [`Credit Report Issuer`](#components) and click on `Get your credit report` button. 
      - Click `Next` on the window and select the `wallet`.
      - The next page shows the `Drivers License` and `Drivers License Assurance` issuer.
      - Select all 2 and click on `Share`.
      - The user data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
      - Click `Proceed Now`, select the `wallet` and click `Connect`. 
   - Details 
     - Credit score Issuer will play two roles here, First role (as RP) to get Drivers License Credential for verifying the user, Second Role (as Issuer) to provide Credit Report for the user.
     - Issuer connects to RP adapter through OIDC protocol.
     - The RP adapter provides following details to wallet through [CHAPI](https://w3c-ccg.github.io/credential-handler-api/).
         - DIDComm Invitation to connect to rp adapter
         - [Presentation Exchange](https://identity.foundation/presentation-exchange/) request
            - Request for Drivers License
            - Request for Authorization to access Drivers License Assurance data
     - For Authorization, the wallet connects to the Issuer Adapter of Drivers License Assurance through 
       [Aries Issue-Credential protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0453-issue-credential-v2) 
       and gets Authorization Credential for users Drivers License Assurance. **Note**: Currently, rp connects directly
       to the issuer without blinding. The `Blinded Routing` feature is planned for subsequent release.
     - Wallet responds with following data through CHAPI.
         - Drivers License Credential
         - Drivers License Assurance Authorization Credential
     - For Authorization Credentials (Drivers License Assurance and Drivers License Assurance), the rp adapter connects to issuer
       adapter through [Aries Present Proof protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2) 
       to get the actual data.
     - RP adapter returns the data to Issuer.
     - The issuer adapter provides following details to wallet through [CHAPI](https://w3c-ccg.github.io/credential-handler-api/).
         - DIDComm Invitation to connect to issuer adapter
         - Manifest Credential with details about Credit Report Issuer
1. Register your property
   - UI Navigation 
      - Navigate to [`Government of Utopia`](#components)'s website and click on `Register Your Property` button.
      - Click `Next` on the window and select the `wallet`.
      - The next page shows the `Drivers License` along with `Drivers License Assurance` and `Credit Report` issuer.
      - Select all 3 and click on `Share`.
      - The user data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
   - Details
     - RP connects to RP adapter through OIDC protocol. 
     - The RP adapter provides following details to wallet through [CHAPI](https://w3c-ccg.github.io/credential-handler-api/).
         - DIDComm Invitation to connect to rp adapter
         - [Presentation Exchange](https://identity.foundation/presentation-exchange/) request
            - Request for Drivers License
            - Request for Authorization to access Drivers License Assurance data
            - Request for Authorization to access Credit Report data
     - For Authorization, the wallet connects to the Issuer Adapter of Drivers License Assurance and Credit Report through 
       [Aries Issue-Credential protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0453-issue-credential-v2) 
       and gets Authorization Credential for users Drivers License Assurance and Credit Report. **Note**: Currently, rp connects directly
       to the issuer without blinding. The `Blinded Routing` feature is planned for subsequent release.
     - Wallet responds with following data through CHAPI.
         - Drivers License Credential
         - Drivers License Assurance Authorization Credential
         - Credit Report Authorization Credential
     - For Authorization Credentials (Drivers License Assurance and Drivers License Assurance), the rp adapter connects to issuer
       adapter through [Aries Present Proof protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2) 
       to get the actual data.
     - RP adapter returns the data to RP.
     
