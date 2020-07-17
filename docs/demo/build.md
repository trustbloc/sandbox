# Edge sandbox - Build

## Prerequisites (General)
- Go 1.13

## Developer Setup
In order to access edge service image and user agent image you have to create personal token with read:packages and repo permissions ([personal token](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line)).
 
Run the following command using your newly generated personal token:

```
docker login -u <username> -p <github token with read:packages and repo permission> docker.pkg.github.com
```
## Prerequisites (for running tests and demos)
- Go 1.13
- Docker
- Docker-Compose
- Make

# Setup CA and hostnames
Run trustbloc-local-setup(`make trustbloc-local-setup`) this target will generate:

- TLS CA located in ~/.trustbloc-local/sandbox/trustbloc-dev-ca.crt (you need to import in cert chain)

- Hosts entries located in ~/.trustbloc-local/sandbox/hosts (you need copy it to /etc/hosts)

## Targets
```
# run checks and unit tests
make all

# run linter checks
make checks

# run unit tests
make unit-test

# start demo components
make demo-start
```

## Demo Components	

The following components are started when you run 'make demo-start':

Edge Components:
- [Edge Service](https://github.com/trustbloc/edge-service) for creating, storing and verifying credentials
- [User Agent](https://github.com/trustbloc/edge-agent/tree/master/cmd/user-agent) is WASM agent for storing and retrieving verifiable credentials using CHAPI

Demo Applications:
- [Issuer](../issuer/README.md)
- [Relying Party](../rp/README.md)

Third Party:
- [ORY Hydra](https://www.ory.sh/docs/hydra/) OAuth2 Server 
- Login/Consent App (simple consent app for Hydra)
- [ORY Oathkeeper](https://www.ory.sh/docs/oathkeeper/#reverse-proxy) deployed in reverse proxy operating mode
- [Strapi](https://strapi.io/documentation/3.0.0-beta.x/getting-started/introduction.html) Content Management Service


## Demo Data

'make demo-start' will also insert demo data into CMS, update ORY Oathkeeper configuration (access rule file) with Strapi admin token and setup up issuer profile for VC service.

You can verify student card data setup by logging in to [admin console](http://localhost:1337/admin) with user strapi (password: strapi).

## Register User Wallet

After you have started sandbox components using 'make demo-start' register user wallet using following step:

Open [user agent register wallet](https://myagent.trustbloc.local/RegisterWallet) and follow the links.

## Demo

To create student card verifiable credential open [issuer home page](https://issuer.trustbloc.local/) and follow the links. You can login as our pre-defined user foo@bar.com or set-up your own user using Strapi admin application.

After creating student card verifiable credential open [rp home page](https://rp.trustbloc.local/) and follow the links.
