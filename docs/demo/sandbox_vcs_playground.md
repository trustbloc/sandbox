# TrustBloc Sandbox - VCS/Non-DIDComm Demo Playground


## References
- [Demo Recording](https://www.youtube.com/watch?v=-EJjxzTLstk)
- [Component Diagram](../components/vcs_components.md)
- [Issuer VCS](https://github.com/trustbloc/vcs/blob/main/docs/vcs/issuer/README.md)
- [Verifier VCS](https://github.com/trustbloc/vcs/blob/main/docs/vcs/verifier/README.md)

## Components
| Component   | Cloud URL (Sandbox)**                                   | Cloud URL (Staging)                                 | Cloud URL (Devel)                                   | Local k8s URL*                                        |
|-------------|---------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------------|-------------------------------------------------------|
| Wallet      | [Click Here](https://wallet.sandbox.trustbloc.dev)      | [Click Here](https://wallet.stg.trustbloc.dev)      | [Click Here](https://wallet.dev.trustbloc.dev)      | [Click Here](https://wallet.local.trustbloc.dev)      |
| Issuer      | [Click Here](https://demo-issuer.sandbox.trustbloc.dev) | [Click Here](https://demo-issuer.stg.trustbloc.dev) | [Click Here](https://demo-issuer.dev.trustbloc.dev) | [Click Here](https://demo-issuer.local.trustbloc.dev) |
| RP/Verifier | [Click Here](https://demo-rp.sandbox.trustbloc.dev)     | [Click Here](https://demo-rp.stg.trustbloc.dev)     | [Click Here](https://demo-rp.dev.trustbloc.dev)     | [Click Here](https://demo-rp.local.trustbloc.dev)     |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.
**: Soon to be deprecated - pre k8s deployment environment

## Steps
1. Login to Wallet:
   - Go to [`Wallet`](#components) and click on `Demo Sign-Up Partner` button.
   - A new window will open with email id and password. 
   - Click on `Sign In` button and it will redirect to `Wallet` dashboard.
1. Issue a Credential : Go to [Demo Issuer](#components), click on  `Issue Permanent Residence Card` in `Issue Local Credentials` 
section. Refer [this](#issuer-options) for more info on issuer profiles and action.
1. Login to the Issuer: With default user email as `john.smith@example.com` and password, click the `Login` button. Consent to 
sharing the data on next page by clicking `Agree` button.
1. Authenticate Wallet with Issuer : 
   - Click on `Authenticate` button and select the registered `wallet`. 
   - In the CHAPI frame,  click on `Connect`. 
   - After success, the page displays the verifiable credential (vc).
1. Store the Credentials in Wallet: Click on `Save your credential`, Give a friendly name and click on `confirm` button.
1. Verify the Credential : Go to [Demo Verifier](#components) and click on `Apply for Home Loan`. Select the `Permanent Residence Card` vc 
when the Wallet asks for a Credential and click `Share`. The next page should show the verification 
status of the credential. 


## Issuer Options
### Profile
Currently, the TrustBloc supports following profiles with different combination of DID method, key type, signature type, credential status in the VC etc
- TrustBloc ED : DID TrustBloc + Ed25519 Key + Ed25519Signature2018 signature type + Credential Status in VC
- TrustBloc JWSE : DID TrustBloc + Ed25519 Key + JsonWebSignature2020 signature type + Credential Status in VC
- TrustBloc JWSP : DID TrustBloc + P256 Key + JsonWebSignature2020 signature type + Credential Status in VC
- Interop ED : DID TrustBloc + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- Interop JWSE : DID TrustBloc + Ed25519 Key + JsonWebSignature2020 signature type + No Credential Status in VC
- Interop JWSP : DID TrustBloc + P256 Key + JsonWebSignature2020 signature type + No Credential Status in VC
- Veres One ED : DID V1 + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- Elem ED : DID Elem + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- Sov ED : DID Sov + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- DID Key ED : DID Key + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- Interop DID Key ED : DID Key + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC

### Actions
- Issue Student Card
- Issue Permanent Resident Card
- Issue VIP Travel Pass
- Issue Crude Product Credential
- Issue University Degree Certificate
- Issue Certified Mill Test Report
- Revoke Credential

