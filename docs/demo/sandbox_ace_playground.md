# TrustBloc Sandbox - Anonymous Comparator and Extractor (ACE) Demo Playground

## Components
| Component                                                                     | Cloud URL (Sandbox)**                                          | Cloud URL (Staging)                                          | Cloud URL (Devel)                                          | Local k8s URL*                                             |
|-------------------------------------------------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------|------------------------------------------------------------|------------------------------------------------------------|
| Utopia Citizenship and Immigration Services (UCIS)                            | [Click Here](https://demo-ucis.sandbox.trustbloc.dev)          | [Click Here](https://ucis-rp.stg.trustbloc.dev)          | [Click Here](https://ucis-rp.dev.trustbloc.dev)          | [Click Here](https://ucis-rp.local.trustbloc.dev)          |
| Utopia Customs and Border Protection (CBP)                                    | [Click Here](https://demo-cbp.sandbox.trustbloc.dev)           | [Click Here](https://cbp-rp.stg.trustbloc.dev)           | [Click Here](https://cbp-rp.dev.trustbloc.dev)           | [Click Here](https://cbp-rp.local.trustbloc.dev)           |
| Utopia Citizenship and Immigration Services (UCIS) Internal Management Portal | [Click Here](https://demo-ucis.sandbox.trustbloc.dev/internal) | [Click Here](https://ucis-rp.stg.trustbloc.dev/internal) | [Click Here](https://ucis-rp.dev.trustbloc.dev/internal) | [Click Here](https://ucis-rp.local.trustbloc.dev/internal) |
| Utopia Federal Benefits Settlement Department                                 | [Click Here](https://demo-benefits-dept.sandbox.trustbloc.dev) | [Click Here](https://benefits-dept-rp.stg.trustbloc.dev) | [Click Here](https://benefits-dept-rp.dev.trustbloc.dev) | [Click Here](https://benefits-dept-rp.local.trustbloc.dev) |

*: Refer [here](./../../README.md#deployment) to run the local k8s demo.
**: Soon to be deprecated - pre k8s deployment environment

## References
- [Comparator Demo Recording](https://www.youtube.com/watch?v=SqDqHSNdGpc)
- [Extractor Demo Recording](https://www.youtube.com/watch?v=E2WHBS6OD2w)

## Comparator Demo Steps
1. Register for an account at `Utopia Citizenship and Immigration Services (UCIS)`:
   - UI Navigation 
     - Go to [`Utopia Citizenship and Immigration Services`](#components) and click on `Complete you profile` button.
     - Enter the Social Security Number (SSN), Email and a password. Note down the details as these would be used in later steps.
     - Clicking `Submit` button would show a success page. 
   - Details 
     - TODO
1. Register for an account at `Utopia Customs and Border Protection (CBP)`:
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
1. Register for an account at `Utopia Citizenship and Immigration Services (UCIS)`:
   - UI Navigation 
     - Go to [`Utopia Citizenship and Immigration Services`](#components) and click on `Complete you profile` button.
     - Enter the Social Security Number (SSN), Email and a password. Note down the details as these would be used in later steps.
     - Clicking `Submit` button would show a success page. 
   - Details 
     - TODO
1. Authorize Access to `Utopia Federal Benefits Settlement Department` to  SSN data from `Utopia Citizenship and Immigration Services (UCIS)`
   - UI Navigation 
     - Go to [`Utopia Citizenship and Immigration Services (UCIS) Internal Management Protal`](#components). The page will show 5 recently created accounts on `UCIS`.
     - Select the users by clicking the checkbox and click on `Authorize Release`.
   - Details 
     - TODO
1. View SSN data at `Utopia Federal Benefits Settlement Department`
   - UI Navigation 
     - Go to [`Utopia Federal Benefits Settlement Department`](#components). The page will show 5 recently created authorization from `UCIS`.
     - Click on `View` to see the Processing details along with SSN data used during creation of account at `UCIS`.
   - Details 
     - TODO
     
