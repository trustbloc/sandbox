# Sandbox - Build and Deployment

## Prerequisites (General)
- Go 1.15
- [git-lfs](https://github.com/git-lfs/git-lfs/blob/master/README.md)

## Prerequisites (for running tests and demos)
- Go 1.15
- Docker
- Make
- [TrustBloc k8s deployment](https://github.com/trustbloc/k8s/blob/main/README.md)

## Targets
```
# run checks and unit tests
make all

# run linter checks
make checks

# run unit tests
make unit-test

# builds the sandbox images, creates k8s cluster and deploys the trustbloc components
make build-setup-deploy

# pulls the sandbox images from remote registry, creates k8s cluster and deploys the trustbloc components 
make setup-deploy

# stops the k8s cluster
make minikube-down
```

## Dependency on trustbloc/k8s repo

The [TrustBloc k8s repo](https://github.com/trustbloc/k8s) contains the scripts to build the following core components.
- adapter
- core-dbs
- csh (Confidential Storage Hub)
- did-method
- edv (Encrypted Data Vault)
- hub-auth
- kms (Key Management Server)
- registrar
- resolver
- sidetree-mock
- vault
- wallet

The k8s scripts for following demo deployments can be found [here](../../k8s). 
- ace-rp (Anonymous Comparator and Extractor)
- cms (Content Management System)
- comparator
- demo-dbs
- issuer
- login-consent
- rp

The make targets in sandbox, pulls the [core deployment repo](../../k8s/scripts/core_deployment.sh) and starts the k8s cluster.
