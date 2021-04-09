# Sandbox - Build

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
