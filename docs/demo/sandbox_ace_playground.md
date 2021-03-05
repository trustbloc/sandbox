# TrustBloc Sandbox - Anonymous Comparator and Extractor (ACE) Demo Playground

## Components
| Component                                          | Cloud URL (Sandbox) | Cloud URL (Dev) | Local URL*                                      |
|----------------------------------------------------|---------------------|-----------------|-------------------------------------------------|
| Utopia Citizenship and Immigration Services (UCIS) |                     |                 | [Click Here](https://ucis-rp.trustbloc.local/) |
| Utopia Customs and Border Protection (CBP)         |                     |                 | [Click Here](https://cbp-rp.trustbloc.local/)   |

*: Refer [here](./build.md) to run the demo locally.

## Comparator Demo Steps
1. Register for an account at Utopia Citizenship and Immigration Services (UCIS):
   - UI Navigation 
     - Go to [`Utopia Citizenship and Immigration Services`](#components) and click on `Complete you profile` button.
     - Enter the Social Security Number (SSN), Email and a password. Note down the details as these would be used in later steps.
     - Clicking `Submit` button would show a success page. 
   - Details 
     - TODO
1. Register for an account at Customs and Border Protection (CBP):
   - UI Navigation 
     - Go to [`Utopia Customs and Border Protection`](#components).
     - Enter the Social Security Number (SSN) and `Click` submit button. The dashboard will show application number.
   - Details 
     - TODO
1. Link UCIS account with CBP account:
   - UI Navigation 
     - On the CBP dashboard page, click on `Redirect me to My UCIS to Link Accounts` button. This will take the user to UCIS login page.
     - Enter the Email and password used to register with UCIS and click `Submit`.
     - On the next page, click on `Agree` to consent to share the access to SSN for validation.
     - If SSN is same on UCIS and CBP, then the page would show `Account Linked Successfully` message, else `Account Not Linked`.
   - Details 
     - TODO


## Extractor Demo Steps
TODOs
