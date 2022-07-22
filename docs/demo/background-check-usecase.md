# Background Check Use Case (OpenID4VC)

**Use Case**: As a user, I should be able to complete my background check using the Permanent Resident Card present in my Digital Wallet.

## Components
| Component                                    | Cloud URL (Sandbox)                                                 | Cloud URL (Staging)                                             | Cloud URL (Devel)                                               | Local k8s URL*                                                    |
|----------------------------------------------|---------------------------------------------------------------------|-----------------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------------|
| User Wallet                                  | [Click Here](https://wallet.sandbox.trustbloc.dev)                  | [Click Here](https://wallet.stg.trustbloc.dev)                  | [Click Here](https://wallet.dev.trustbloc.dev)                  | [Click Here](https://wallet.local.trustbloc.dev)                  |
| Permanent Residence Card Issuer              | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/applyprcard) | [Click Here](https://demo-issuer.stg.trustbloc.dev/applyprcard) | [Click Here](https://demo-issuer.dev.trustbloc.dev/applyprcard) | [Click Here](https://demo-issuer.local.trustbloc.dev/applyprcard) |
| Background Check Service Provider (Verifier) | [Click Here](https://demo-rp.sandbox.trustbloc.dev/backgroundcheck) | [Click Here](https://demo-rp.stg.trustbloc.dev/backgroundcheck) | [Click Here](https://demo-rp.dev.trustbloc.dev/backgroundcheck) | [Click Here](https://demo-rp.local.trustbloc.dev/backgroundcheck) |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.

## Flow details
1. Login to Wallet:
   - Go to [`Wallet`](#components) and click on `Demo Sign-Up Partner` button.
   - A new window will open with email id and password. 
   - Click on `Sign In` button and it will redirect to `Wallet` dashboard.
1. Issue Permanent Resident Card:
   - Go to [`Permanent Residence Card Issuer`](#components) website.
   - Click on `Apply for your Digital Permanent Resident Card`.
   - Login to the Issuer with default username and password. 
   - The next page will show `Permanent Residence Card` preview.
   - Click on `Save`.
1. Verify Permanent Resident Card:
   - Go to [`Background Check Provider`](#components) website.
   - Click on `Click here to initiate`.
   - The next page will show `Permanent Residence Card` preview.
   - Click on `Share`.
   - Success page will be displayed