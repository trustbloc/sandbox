# TrustBloc Sandbox - VCS/Non-DIDComm Demo Playground

## Components
| Component   | Cloud URL (Sandbox)                                         | Cloud URL (Dev)                                            | Local k8s URL*                                     |
|-------------|-------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------------|
| Wallet      | [Click Here](https://agent.sandbox.trustbloc.dev/dashboard) | [Click Here](https://agent-ui.dev.trustbloc.dev/dashboard) | [Click Here](https://wallet.local.trustbloc.dev)   |
| Issuer      | [Click Here](https://demo-issuer.sandbox.trustbloc.dev)     | [Click Here](https://demo-issuer.dev.trustbloc.dev)        | [Click Here](https://issuer.local.trustbloc.dev)   |
| RP/Verifier | [Click Here](https://demo-verifier.sandbox.trustbloc.dev)   | [Click Here](https://demo-verifier.dev.trustbloc.dev)      | [Click Here](https://rp.local.trustbloc.dev)       |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.

## Steps
1. Login to Wallet : Go to [Wallet](#components) and click on `Allow` when a pop-up asks for the permission. This 
registers the `Wallet` with CHAPI internally.
2. Register a Wallet identity : Go to `DID Management` tab of [`Wallet`](#components) and 
create a new TrustBloc DID by selecting the key type (Ed25519 or P256) and signature type (Ed25519Signature2018 or 
JsonWebSignature2020). Type in a friendly name and click save. If successful, the new DID shows up in the table. Refer 
[this](#wallet-dids) for more info on supported DIDs.
3. Issue a Credential : Go to [Demo Issuer](#components), click on  `Issue Permanent Residence Card` in `Issue Local Credentials` 
section, select `TrustBloc ED` and click `issue` button. Refer [this](#issuer-options) for more info on issuer profiles and action.
4. Login to the Issuer: With default user email as `john.smith@example.com` and password, click the `Login` button. Consent to 
sharing the data on next page by clicking `Agree` button.
5. Authenticate Wallet with Issuer : Click on `Authenticate` button select the registered `wallet`. 
Select a wallet identity (subject DID) and click `Authenticate`. After success, the page displays the verifiable credential (vc).
6. Store the Credentials in Wallet: Click on `Save your credential`, Give a friendly name and click on `confirm` button.
7. Verify the Credential : Go to [Demo Verifier](#components) and click on `Apply for Home Loan`. Select the `Permanent Residence Card` vc 
when the Wallet asks for a Credential and click `Share`. The next page should show the verification 
status of the credential. 

## Wallet DIDs
On the [DID Management](#components) tab, go to `Save Any DID` and enter DID information 
on the page to use it as a wallet indentity.

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

