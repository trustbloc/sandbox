# TrustBloc Edge Sandbox - Demo Playground

The components from this repo are deployed on a server to play around without running locally.

## Components
1. [Wallet](https://agent.sandbox.trustbloc.dev/dashboard)
2. [Issuer](https://demo-issuer.sandbox.trustbloc.dev/)
3. [Verifier](https://demo-verifier.sandbox.trustbloc.dev/) 

## Steps
1. Register a Wallet identity : Go to [DID Management](https://agent.sandbox.trustbloc.dev/DIDManagement) and 
create a new TrustBloc DID by selecting the key type (Ed25519 or P256) and signature type (Ed25519Signature2018 or 
JsonWebSignature2020). Type in a friendly name and click save. If successful, the new DID shows up in the table. Refer [this](#wallet-dids) 
for more info on supported DIDs.
2. Register the Wallet (CHAPI) : Go to [Register Wallet](https://agent.sandbox.trustbloc.dev/RegisterWallet) and click 
on `Allow` when a pop-up asks for the permission.
3. Issue a Credential : Go to [Demo Issuer](https://demo-issuer.sandbox.trustbloc.dev/), select `interop-ed25519signature2018-ed25519` 
profile and `Issue University Degree Certificate` action and click `submit` button. Refer [this](#issuer-options) for more info on issuer profiles and action.
4. Login to the Issuer: On the landing page of the `university`, click on `Issue University Degree Certificate`. One the 
next page, provide user email as `foo@bar.com` (no password) and click login. Consent to sharing the data on next page by clicking
`Allow Access`.
5. Authenticate Wallet with Issuer : Click on `Authenticate` button select the wallet `agent.sandbox.trustbloc.dev`. 
Select a wallet identity (subject DID) and click `Authenticate`. 
6. Store the Credentials in Wallet: Click on `Retrieve Credential` and the Verifiable Credential (VC) document shows up. 
Now click on `Store VC in Wallet`. Give a friendly name and click on `confirm` button.
7. Verify the VC : Go to [Demo Verifier](https://demo-verifier.sandbox.trustbloc.dev/) and click on `Get your VC directly from wallet`. 
Select a VC from the Wallet it it asks for a Credential and click `Share`. The next page should show the verification 
status of the VC. 
8. Verify the VP : Go to [Demo Verifier](https://demo-verifier.sandbox.trustbloc.dev/), inside `Choose your credential to verify`, 
select `University Degree Certificat` dropdown value in `Choose your credential to verify` and click on it. Select wallet identity used during saving the VC, chose the credential
and click `Share`. The next page should show the verification status of the VP. 

## Wallet DIDs
On the [DID Management](https://agent.sandbox.trustbloc.dev/DIDManagement) page, go to `Save Any DID` and enter DID information 
on the page to use it as a wallet indentity.

## Issuer Options
### Profile
Currently, the TrustBloc supports following profiles with different combination of DID method, key type, signature type, credential status in the VC etc
- trustbloc-ed25519signature2018-ed25519 : DID TrustBloc + Ed25519 Key + Ed25519Signature2018 signature type + Credential Status in VC
- trustbloc-jsonwebsignature2020-ed25519 : DID TrustBloc + Ed25519 Key + JsonWebSignature2020 signature type + Credential Status in VC
- trustbloc-jsonwebsignature2020-p256 : DID TrustBloc + P256 Key + JsonWebSignature2020 signature type + Credential Status in VC
- interop-ed25519signature2018-ed25519 : DID TrustBloc + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- interop-jsonwebsignature2020-ed25519 : DID TrustBloc + Ed25519 Key + JsonWebSignature2020 signature type + No Credential Status in VC
- interop-jsonwebsignature2020-p256 : DID TrustBloc + P256 Key + JsonWebSignature2020 signature type + No Credential Status in VC
- vc-issuer-interop-key : DID Key + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- vc-issuer-interop : DID TrustBloc + P256 Key + JsonWebSignature2020 signature type + No Credential Status in VC
- verseone-ed25519signature2018-ed25519 : DID V1 + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- elem-ed25519signature2018-ed25519 : DID Elem + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- sov-ed25519signature2018-ed25519 : DID Sov + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC
- didkey-ed25519signature2018-ed25519 : DID Key + Ed25519 Key + Ed25519Signature2018 signature type + No Credential Status in VC

### Actions
- Issue HighTech CollegeCard
- Issue University Degree Certificate
- Issue VIP Travel Card
- Issue Permanent Resident Card
- Issue Certified Mill Test Report
- Issue Crude Product Credentia
- Issuer Kiosk
- Revoke Credential

