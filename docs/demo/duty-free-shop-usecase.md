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
   - Go to [`Permanent Residence Card Issuer`](#components) website.
   - Click on `Issue Permanent Resident Card (WACI)`.
   - Login to the Issuer with default user email as `john.smith@example.com` and password, click the `Login` button. Consent to sharing the data on next page by clicking `Agree` button.
   - On the next page, chose one of the following option available to present the Permanent Resident Card
     - Redirect to Wallet
       - Click on `Click here to redirect to your wallet`
       - The next page will show `Permanent Residence Card` previw.
       - Click on `Save`.
     - Scan QR Code
       - After Scanning the QR code, the mobile browser will open
       - The next page will show `Permanent Residence Card` previw.
       - Click on `Save`.
1. Verify Permanent Resident Card:
   - Go to [`Duty Free Shop`](#components) website.
   - On the next page, chose one of the following option available to present the Permanent Resident Card
     - Redirect to Wallet
       - Click on `Click here to redirect to your wallet`
       - If user is not signed-in, then wallet sign-in page will be showed
         - On the `Wallet` sign-in page, click on the `Demo Sign-In Partner`.
         - Enter the the same `email` id used to login.
       - The next page will show `Permanent Residence Card` preview
       - Click on `Share`.
       - Click `OK` on the success page.
       - The PRC data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
     - Scan QR Code
       - After Scanning the QR code, the mobile browser will open
       - If user is not signed-in, then wallet sign-in page will be showed
         - On the `Wallet` sign-in page, click on the `Demo Sign-In Partner`.
         - Enter the the same `email` id used to login and save the PRC.
       - The next page will show `Permanent Residence Card` in the list
       - Click on `Share`.
       - Click `OK` on the success page.
       - The PRC data will be displayed on the page with `success message`. Click `source` tab to view the raw json data.
