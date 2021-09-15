# Duty Free Shop Use Case (WACI-Share)

**Use Case**: As a user, I should be able to buy items by confirming my age from the Permanent Resident Card present in my Digital Wallet.

## Components
| Component                         | Cloud URL (Sandbox)                                                    | Cloud URL (Staging)                                                | Cloud URL (Devel)                                                  | Local k8s URL*                                                       |
|-----------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------|
| User Wallet                       | [Click Here](https://wallet.sandbox.trustbloc.dev)                     | [Click Here](https://wallet.stg.trustbloc.dev)                     | [Click Here](https://wallet.dev.trustbloc.dev)                     | [Click Here](https://wallet.local.trustbloc.dev)                     |
| Permanent Residence Card Issuer   | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/applygreencard) | [Click Here](https://demo-issuer.stg.trustbloc.dev/applygreencard) | [Click Here](https://demo-issuer.dev.trustbloc.dev/applygreencard) | [Click Here](https://demo-issuer.local.trustbloc.dev/applygreencard) |
| Duty Free Shop (Verifier) | [Click Here](https://demo-rp.sandbox.trustbloc.dev/dutyfree)             | [Click Here](https://demo-rp.stg.trustbloc.dev/dutyfree)             | [Click Here](https://demo-rp.dev.trustbloc.dev/dutyfree)             | [Click Here](https://demo-rp.local.trustbloc.dev/dutyfree)             |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.

## Flow details
1. Login to Wallet:
   - Go to [`Wallet`](#components) and click on `Demo Sign-Up Partner` button.
   - A new window will open with email id and password. 
   - Click on `Sign In` button and it will redirect to `Wallet` dashboard.
1. Issue Permanent Resident Card:
   - Go to [`Permanent Residence Card Issuer`](#components).
   - Look for `Apply for your Digital Green Card` button and click on it.
   - Click `Submit` without changing email/password.
   - Click on `Submit` button on the `Digital Green Card Application Lookup`.
   - Click on `Connect To Wallet` button and which would open [CHAPI](https://w3c-ccg.github.io/credential-handler-api/) window.
   - Select the `Wallet` from the list and click on it.
   - The `CHAPI` window will show list of Digital Identities (refer step #2).
   - Select one and click `Authenticate`.
   - The next screen will show the `Digital Permanent Resident Card`.
   - Click on `Save Credential`.
   - Select the `Wallet` from the list and click on it.
   - Click on `Confirm` button and a success page would be shown.
1. Verify Permanent Resident Card:
   - Go to [`Duty Free Shop`](#components) website.
   - On the next page, chose one of the following option to present the Permanent Resident Card
     - Redirect to Wallet
       - Click on `Click here to redirect to your wallet`
       - If user is not signed-in, then wallet sign-in page will be showed
         - On the `Wallet` sign-in page, click on the `Demo Sign-In Partner`.
         - Enter the the same `email` id used to login and save the PRC.
       - The next page will show `Permanent Residence Card` in the list
       - Click on `Agree`.
       - The PRC data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
     - Scan QR Code
       - After Scanning the QR code, the mobile browser will open
       - If user is not signed-in, then wallet sign-in page will be showed
         - On the `Wallet` sign-in page, click on the `Demo Sign-In Partner`.
         - Enter the the same `email` id used to login and save the PRC.
       - The next page will show `Permanent Residence Card` in the list
       - Click on `Agree`.
       - The PRC data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
     - CHAPI Selector
       - Click on `CHAPI Wallet`
       - Select the `Wallet` from the list and click on it.
       - The next page will show `Permanent Residence Card` in the list
       - Click on `Agree` to share the credential.
       - The PRC data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.

