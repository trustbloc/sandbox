# New Bank Account Use Case

**Use Case**: As a user, I should be able to open a new bank account online by providing my digital 
drivers license, digital drivers license assurance/evidence and digital credit report.

## References
- [Demo Recording](https://www.youtube.com/watch?v=0ZNmk6E2EFE&feature=youtu.be)
- [Component Diagram](../images/adapter_component_diagram.svg)
- [Issuer Adapter](https://github.com/trustbloc/edge-adapter/blob/main/docs/issuer/README.md)
- [RP Adapter](https://github.com/trustbloc/edge-adapter/blob/main/docs/rp/README.md)

## Components
| Component                          | Cloud URL (Sandbox)**                                                  | Cloud URL (Staging)                                                    | Cloud URL (Devel)                                                    | Local k8s URL*                                                       |
|------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------|----------------------------------------------------------------------|
| User Wallet                        | [Click Here](https://wallet.sandbox.trustbloc.dev)                      | [Click Here](https://wallet.stg.trustbloc.dev)                     | [Click Here](https://wallet.dev.trustbloc.dev)                     | [Click Here](https://wallet.local.trustbloc.dev)                     |
| Bank                               | [Click Here](https://demo-rp.sandbox.trustbloc.dev/bankaccount)  | [Click Here](https://demo-rp.stg.trustbloc.dev/bankaccount)        | [Click Here](https://demo-rp.dev.trustbloc.dev/bankaccount)        | [Click Here](https://demo-rp.local.trustbloc.dev/bankaccount)        |
| Drivers License + Assurance Issuer | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/drivinglicense) | [Click Here](https://demo-issuer.stg.trustbloc.dev/drivinglicense) | [Click Here](https://demo-issuer.dev.trustbloc.dev/drivinglicense) | [Click Here](https://demo-issuer.local.trustbloc.dev/drivinglicense) |
| Credit Report Issuer               | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/creditscore)    | [Click Here](https://demo-issuer.stg.trustbloc.dev/creditscore)    | [Click Here](https://demo-issuer.dev.trustbloc.dev/creditscore)    | [Click Here](https://demo-issuer.local.trustbloc.dev/creditscore)    |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.
**: Soon to be deprecated - pre k8s deployment environment

## Flow details
1. Login to Wallet:
   - UI Navigation 
     - Go to [`Wallet`](#components) and click on Login button with default user name and password.
   - Details 
     - A new [DID]((https://w3c.github.io/did-core/)) (identity) gets created for the user.
     - The `Wallet` registers with the [DIDComm Mediator/Router](https://github.com/hyperledger/aries-framework-go/blob/main/docs/didcomm_mediator.md).
1. Get Drivers License and Connect to Assurance Issuer: 
   - UI Navigation 
     - On [`Drivers License + Assurance Issuer`](#components) page, click on `Issue Driving Licence` button. 
     - Login to the account with default username/password and click `agree` on the consent page.
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
      - Login to the account with default username/password and click `agree` on the consent page.
      - Click `Next` on the window, select the `wallet` and click `Connect`. 
   - Details 
     - The issuer adapter provides following details to wallet through [CHAPI](https://w3c-ccg.github.io/credential-handler-api/).
         - DIDComm Invitation to connect to issuer adapter
         - Manifest Credential with details about Credit Report Issuer
1. Open a Bank Account
   - UI Navigation 
      - Navigate to [`Bank`](#components)'s website and click on `Open Bank Account` button.
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
     
