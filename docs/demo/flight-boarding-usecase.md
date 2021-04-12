# Flight Boarding Use Case

**Use Case**: As a user, I should be able to board a flight by showing my Permanent Resident Card, Flight Booking 
Reference and selectively disclose few attributes from Vaccination Certificate.

## References
- [Demo Recording](https://youtu.be/bKUu_uK-FlM)

## Components
| Component                                            | Cloud URL (Sandbox)                                                     | Cloud URL (Dev)                                                     | Local k8s URL*                                                 |
|------------------------------------------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------|----------------------------------------------------------------|
| User Wallet                                          | [Click Here](https://agent.sandbox.trustbloc.dev)                       | [Click Here](https://agent-ui.dev.trustbloc.dev)                    | [Click Here](https://wallet.local.trustbloc.dev)               |
| Permanent Residence Card Issuer                      | [Click Here](https://demo-issuer.sandbox.trustbloc.dev)                 | [Click Here](https://demo-issuer.dev.trustbloc.dev)                 | [Click Here](https://issuer.local.trustbloc.dev)               |
| Vaccination Certificate Card Issuer                  | [Click Here](https://demo-issuer.sandbox.trustbloc.dev)                 | [Click Here](https://demo-issuer.dev.trustbloc.dev)                 | [Click Here](https://issuer.local.trustbloc.dev)               |
| Taylor Chartered Flight- Booking (Issuer)            | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/flightbooking)   | [Click Here](https://demo-issuer.dev.trustbloc.dev/flightbooking)   | [Click Here](https://issuer.local.trustbloc.dev/flightbooking) |
| Taylor Chartered Flight- Checkin/Boarding (Verifier) | [Click Here](https://demo-verifier.sandbox.trustbloc.dev/flightcheckin) | [Click Here](https://demo-verifier.dev.trustbloc.dev/flightcheckin) | [Click Here](https://rp.local.trustbloc.dev/flightcheckin)     |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.

## Flow details
1. Login to Wallet:
   - Go to [`Wallet`](#components) and click on `Sign In/Register` button.
   - On the next page, select `Universal Bank` and provide any email id and password. 
   - Clicking on `Agree` button to accept `Terms of Service` would show the `Wallet` dashboard.
1. Register a Wallet identity:
   - Go to `Digital Identity Management` tab on the sidebar.
   - Select `Key Type` and `Signature Type` from drop down in `Create New TrustBloc Digital Identiy` section.
   - Enter a `Friendly Name` anc click `Create and Save Digtital Identity` button.
   - On success, `Digital Identity` table gets updated with this new identity.
1. Issue Permanent Resident Card:
   - Go to [`Permanent Residence Card Issuer`](#components).
   - Look for `Issue Permnanent Card` button and click on it.
   - Click `Login` without changing email/password.
   - Click on `Agree` button on the consent page.
   - Click on `Authenticate` button and which would open [CHAPI](https://w3c-ccg.github.io/credential-handler-api/) window.
   - Select the `Wallet` from the list and click on it.
   - The `CHAPI` window will show list of Digital Identities (refer step #2).
   - Select one and click `Authenticate`.
   - The next screen will show the `Verifiable Credential`.
   - Click on `Save you credential`.
   - Select the `Wallet` from the list and click on it.
   - Click on `Confirm` button and a success page would be shown. Note: The system will populate a default friendly name. This can be overridden by the user.
1. Issue Vaccination Certificate:
   - Go to [`Vaccination Certificate Card Issuer`](#components).
   - Look for `Issue Vaccination Certificate` button and click on it.
   - Click `Login` without changing email/password.
   - Click on `Agree` button on the consent page.
   - Click on `Authenticate` button and which would open [CHAPI](https://w3c-ccg.github.io/credential-handler-api/) window.
   - Select the `Wallet` from the list and click on it.
   - The `CHAPI` window will show a list of Digital Identities (refer step #2).
   - Select one and click `Authenticate`.
   - The next screen will show the `Verifiable Credential`.
   - Click on `Save you credential`.
   - Select the `Wallet` from the list and click on it.
   - Clicking on `Confirm` button, a success page would be shown. Note: The system will populate a default friendly name. This can be overridden by the user.
1. Book a Flight:
   - Go to [`Taylor Chartered Flight- Booking (Issuer)`](#components).
   - The page will display a booking reference number.
   - Click on `Link Wallet` button.
   - Select the `Wallet` from the list and click on it.
   - The `CHAPI` window will show a list of Digital Identities (refer step #2).
   - Select one and click `Authenticate`.
   - After successful validation, `Collect Booking Ref` button gets enabled.
   - Clicking on `Collect Booking Ref` button, will open `CHAPI` window to save the booking data.
   - Select the `Wallet` from the list and click on it.
   - Clicking on `Confirm` button, a success page would be shown. Note: The system will populate a default friendly name. This can be overridden by the user.
1. Flight Check-in/Boarding:
   - Go to [`Taylor Chartered Flight- Checkin/Boarding (Verifier)`](#components).
   - Click on `Check-in` button in the `Digital Check-in` section.
   - The next page will show list of required data from the user to check-in (booking reference, Permanent Residence and Vaccination Certificate details). 
   - Clicking on `Proceed in Browser` will open `CHAPI` window.
   - Select the `Wallet` from the list and click on it.
   - The page will show the credentials available in the User `Wallet`.
   - Click on `Agree` to share the credentials.
   - The system will display success screen (with green check mark).
