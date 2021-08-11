## Issuer - OAuth2 client services

### Flow diagram
![Issuer - OAuth client services flow diagram](./issuer_oauth2_flow.svg)


### Components
| Component                                     | Source URL                                          |
|-----------------------------------------------|-----------------------------------------------------|
| Demo Issuer                                   | [Source](https://github.com/trustbloc/sandbox)      |
| Demo IDMS (ORY Hydra)                         | [Source](https://github.com/ory/hydra)              |
| Demo Identity & Access Proxy (ORY Oathkeeper) | [Source](https://github.com/ory/oathkeeper)         |
| Demo CMS (Strapi)                             | [Source](https://github.com/strapi/strapi)          |
| Issuer HTTP API                               | [Source](https://github.com/trustbloc/edge-service) |
| Wallet                                        | [Source](https://github.com/trustbloc/wallet)       |

### PRC Demo

| Environment | URL                                                                    |
|-------------|------------------------------------------------------------------------|
| Sandbox     | [Click Here](https://demo-issuer.sandbox.trustbloc.dev/applygreencard) |
| Staging     | [Click Here](https://demo-issuer.stg.trustbloc.dev/applygreencard)     |
| Dev         | [Click Here](https://demo-issuer.dev.trustbloc.dev/applygreencard)     |
| Local       | [Click Here](https://demo-issuer.local.trustbloc.dev/applygreencard)   |



### APIs
#### Redirection to Demo IDMS (ORY Hydra) from Demo Issuer
Refer [OAuth2 Authorization Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)

example;
https://hydra.sandbox.trustbloc.dev/oauth2/auth?client_id=auth-code-client&redirect_uri=https%3A%2F%2Fdemo-issuer.sandbox.trustbloc.dev%2Fcallback&response_type=code&state=h0TylPnVIAq17pphkeQm3Q%3D%3D&scope=PermanentResidentCard

#### Callback from Demo IDMS (ORY Hydra) to Demo Issuer
Refer [OAuth2 Authorization Response](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2)

example;
https://demo-issuer.dev.trustbloc.dev/callback?code=darY1tyVTlg7amnnrO_c1Pp9u9y5h9kKGWNufUHmGKU.NxZ2ort1JgU4rWaDRqmt_2MpoAHF5mG6C4vbbIa_H5M&scope=PermanentResidentCard&state=AqCYrsjzJJlp3-5SrcYWig%3D%3D


### Get Access token using auth code
Refer [OAuth2 Access Token Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)

### Get user data using Access token from Demo CMS
#### Request
HTTP GET 
HEADER: 'Authorization"="Bearer <accessToken>"
https//cms.dev.trustbloc.dev/<scope>?userid=<userid>

example:
https://oathkeeper-proxy.dev.trustbloc.dev/permanentresidentcard?userid=100

#### Response
```json
{
   "userid":"100",
   "vcmetadata":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://w3id.org/citizenship/v1"
      ],
      "name":"Permanent Resident Card",
      "description":"Permanent Resident Card of Mr.Louis Pasteur"
   },
   "vccredentialsubject":{
      "birthCountry":"Bahamas",
      "birthDate":"1958-07-17",
      "familyName":"Pasteur",
      "gender":"Male",
      "givenName":"Louis",
      "id":"did:trustbloc:||BLOC_DOMAIN||:EiD6cBirl2gND93LLKQzDMX4XjR3F7W2v4dPJzd8bQpPYQ",
      "lprCategory":"C09",
      "lprNumber":"999-999-999",
      "residentSince":"2015-01-01",
      "type":[
         "Person",
         "PermanentResident"
      ]
   }
}
```

### Demo Issuer configurations
#### Demo IDMS (ORY Hydra)
[Refer](https://github.com/trustbloc/sandbox/blob/c254ac065ee30d4f1110ad13d6b34f60113be162/k8s/issuer/kustomize/issuer/overlays/common/config.env#L14-L17) for Demo IDMS OAuth configuration in Demo Issuer.

#### Demo Identity & Access Proxy (ORY Oathkeeper)
[Refer](https://github.com/trustbloc/sandbox/blob/c254ac065ee30d4f1110ad13d6b34f60113be162/k8s/issuer/kustomize/issuer/overlays/common/config.env#L10) for CMS configuration in Demo Issuer.


### Demo Issuer UI source
The HTML files used in Demo Issuer can be found [here](https://github.com/trustbloc/sandbox/tree/main/cmd/issuer-rest/static). 
