## Issuer

Issuer is a sample application that demonstrates creation of verifiable credentials. 

Issuer application will:
- authenticate user 
- ask for user consent for data sharing
- retrieve user data from content management system
- call [vc service](https://github.com/trustbloc/vcs) to create student card verifiable credential on behalf of the issuer
- present student card verifiable credential to the user
- create the QR Code for retrieving the verifiable credential 
  
   Note: In order to scan the QR code from your phone browser you need to be in the same network where your application is running. 
     - Replace "127.0.0.1" in the following files to your machine's IP address:
       - test/bdd/fixtures/demo/docker-compose-demo-applications.yml 
       - test/bdd/fixtures/demo/docker-compose-third-party.yml 
       - test/bdd/fixtures/scripts/hydra_configure.sh
- scan the QRcode from any camera facing device.
