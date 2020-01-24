# Aries Framework Go - Build

## Prerequisites (General)
- Go 1.13

## Developer Setup
In order to access edge service image and user agent image you have to create personal token with read:packages and repo permissions ([personal token](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line)).
 
Run the following command using your newly generated personal token:

docker login -u <username> -p <github token with read:packages permission> docker.pkg.github.com

## Prerequisites (for running tests and demos)
- Go 1.13
- Docker
- Docker-Compose
- Make

## Targets
```
# run checks and unit tests
make all

# run linter checks
make checks

# run unit tests
make unit-test

# start sandbox components
make sandbox-start
```

## Strapi Data Setup

After you have started [sandbox components](#Sandbox) using 'make sandbox-start' set up test data using following command:

make strapi-setup

This command will also update ORY Oathkeeper configuration (access rule file) with Strapi admin token.

You can verify student card data setup by logging in to [admin console](http://localhost:1337/admin) with user strapi (password: strapi).

## Demo

To create student card verifiable credential open [issuer home page](https://127.0.0.1:5556/) and follow the links.

##Sandbox Components	

The following components are started when you run 'make sandbox-start':

Edge Components:
- [Edge Service](https://github.com/trustbloc/edge-service) for creating, storing and verifying credentials
- [User Agent](https://github.com/trustbloc/edge-agent/tree/master/cmd/user-agent) is WASM agent for storing and retrieving verifiable credentials using CHAPI

Demo Applications:
- [Issuer](https://github.com/trustbloc/edge-sandbox/docs/issuer/README.md)
- [Relying Party](https://github.com/trustbloc/edge-sandbox/docs/rp/README.md)

Third Party:
- [ORY Hydra](https://www.ory.sh/docs/hydra/) OAuth2 Server 
- Login/Consent App (simple consent app for Hydra)
- [ORY Oathkeeper](https://www.ory.sh/docs/oathkeeper/#reverse-proxy) deployed in reverse proxy operating mode
- [Strapi](https://strapi.io/documentation/3.0.0-beta.x/getting-started/introduction.html) Content Management Service