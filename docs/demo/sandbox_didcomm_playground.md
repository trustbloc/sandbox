# TrustBloc Edge Sandbox - DIDComm Demo Playground

Note : The components are not deployed on the cloud and need to be run locally. Refer [build](build.md) for 
instruction on local deployment.

## Components
1. [Wallet](https://myagent.trustbloc.local/dashboard)
2. [Issuer](https://issuer.trustbloc.local/)
3. [RP](https://rp.trustbloc.local/) 

## Demo Recording
- [DIDComm Demo Recording](https://www.youtube.com/watch?v=yDCIGiNeFrI&feature=youtu.be) 

## Steps
1. Login to Wallet : Go to [`Wallet`](https://myagent.trustbloc.local/dashboard) and click on `Login` button with pre-filled username and password. 
2. Select DIDComm option : In the [`Issuer`](https://issuer.trustbloc.local/) page, click on `Share Credit Card Statement` option in `Choose your options (DIDComm)` 
section. Select `TrustBloc ED` profile and click `Issue`. Refer [here](#issuer-options) for more info on available issuer actions and profiles.
3. Login to the Issuer: On the login page, provide user email as `foo@bar.com` (no password) and click login. Now, consent to sharing the 
data on next page by clicking `Allow Access`. This will redirect to `Issuer Adapter` page and opens a CHAPI window.
4. Connect to Wallet : Select `myagent.trustbloc.local` wallet provider from the options shown in the CHAPI window and click on it. Click `Allow` to continue with the 
connection request. Once connected, the `Issuer Adapter` redirects to Issuer with a success message.
5. Retrieve OIDC ID_TOKEN in RP : Go to [`RP`](https://rp.trustbloc.local/) and click on `Apply for New Credit Card`. This will redirect to `RP Adapter` page and 
opens a CHAPI window. Select `myagent.trustbloc.local` wallet provider from the options shown in the CHAPI window and click on it. The next page will 
show the requested data from the `RP`. Select `TrustBloc - Credit Card Data Issuer` and click on `Share`. The screen will be redirected to `RP` displaying 
Credit Card data inside the OIDC ID token.  

## Issuer Options
### Actions
- Share Credit Card Statement

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

