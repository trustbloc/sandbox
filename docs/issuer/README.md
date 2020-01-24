## Issuer

Issuer is a sample application that demonstrates creation of verifiable credentials. 

Issuer application will:
- authenticate user 
- ask for user consent for data sharing
- retrieve user data from content management system
- call [edge service](https://github.com/trustbloc/edge-service) to create student card verifiable credential on behalf of the issuer
- present student card verifiable credential to the user
