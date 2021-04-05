# TrustBloc Sandbox - Adapter/DIDComm Demo Playground

## Components
| Component   | Cloud URL (Sandbox)                                       | Cloud URL (Dev)                                       | Local k8s URL*                              | Local URL**                                   |
|-------------|-----------------------------------------------------------|-------------------------------------------------------|---------------------------------------------|-----------------------------------------------|
| Wallet      | [Click Here](https://agent.sandbox.trustbloc.dev)         | [Click Here](https://agent-ui.dev.trustbloc.dev)      | [Click Here](https://myagent.trustbloc.dev) | [Click Here](https://myagent.trustbloc.local) |
| Issuer      | [Click Here](https://demo-issuer.sandbox.trustbloc.dev)   | [Click Here](https://demo-issuer.dev.trustbloc.dev)   | [Click Here](https://issuer.trustbloc.dev)  | [Click Here](https://issuer.trustbloc.local)  |
| RP/Verifier | [Click Here](https://demo-verifier.sandbox.trustbloc.dev) | [Click Here](https://demo-verifier.dev.trustbloc.dev) | [Click Here](https://rp.trustbloc.dev)      | [Click Here](https://rp.trustbloc.local)      |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.

**: Refer [here](./build.md) to run the demo locally.

## Demo Recording
- [DIDComm Demo Recording](https://www.youtube.com/watch?v=yDCIGiNeFrI&feature=youtu.be) 

## Steps
1. Login to Wallet : Go to [`Wallet`](#components) and click on `Login` button with pre-filled username and password. 
2. Select DIDComm option : In the [`Issuer`](#components) page, click on `Share Credit Card Statement` option in `Choose your options (DIDComm)` 
section. Refer [here](#issuer-options) for more info on available issuer actions.
3. Login to the Issuer: On the login page, provide user email as `john.smith@example.com` (no password) and click login. Now, consent to sharing the 
data on next page by clicking `Allow Access`. This will redirect to `Issuer Adapter` page and opens a CHAPI window.
4. Connect to Wallet : Select the registered [`Wallet`](#components) provider from the options shown in the CHAPI window and click on it. Click `Allow` to continue with the 
connection request. Once connected, the `Issuer Adapter` redirects to Issuer with a success message.
5. Retrieve OIDC ID_TOKEN in RP : Go to [`RP`](#components) and click on `Apply for New Credit Card`. This will redirect to `RP Adapter` page and 
opens a CHAPI window. Select `myagent.trustbloc.local` wallet provider from the options shown in the CHAPI window and click on it. The next page will 
show the requested data from the `RP`. Select `TrustBloc - Credit Card Data Issuer` and click on `Share`. The screen will be redirected to `RP` displaying 
Credit Card data inside the OIDC ID token.  

## Issuer Options
### Actions
- Share Credit Card Statement
