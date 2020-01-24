## Relaying Party

Relying Party is a sample application that will request verifiable credential (VC) from the user. 

Relying Party application will:
- request VC from the user via [CHAPI](https://github.com/digitalbazaar/credential-handler-polyfill) 
- verify if VC is valid against [Edge Service](https://github.com/trustbloc/edge-service)