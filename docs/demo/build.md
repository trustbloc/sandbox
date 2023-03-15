# Sandbox - Build and Deployment

## Prerequisites (General)
- go 1.19
- [git-lfs](https://github.com/git-lfs/git-lfs/blob/master/README.md)

## Prerequisites (for running tests and demos)
- go 1.19
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
- orb
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

## (Re-)deploying single component
Change directory to the specific component and run `make deploy`
```
# sandbox component
cd ./k8s/$COMPONENT && make deploy

# core component
cd ./k8s/.core/$COMPONENT && make deploy
```
### Using local copy of the *core* `trustbloc/k8s` components for deployment
By default *core* components are pulled from the `trustbloc/k8s` git repo, specific commit ID is used which is set by the  `TRUSTBLOC_CORE_K8S_COMMIT` variable in `./Makefile`. 
<br>To override this and use the locally cloned copy of the `trustbloc/k8s`, the following line needs to be uncommented: https://github.com/trustbloc/sandbox/blob/main/k8s/scripts/core_deployment.sh#L21. In this case `./k8s/.core` directory will be linked to the provided local copy of `trustbloc/k8s`.
## Sandbox local deployment steps

Makefiles involved: 
* `./Makefile`
* `./k8s/Makefile`
* `./k8s/$COMPONENT/Makefile`
* `./k8s/.core/Makefile`
* `./k8s/.core/$COMPONENT/Makefile`

Scripts involved:
* `./k8s/scripts:   deploy_all.sh, minikube_setup.sh, core_deployment.sh`
* `./k8s/.core/scripts: deploy_all.sh`

### Local deployment steps sequence:
* manually clone github repo: `trustbloc/sandbox`
* manually run comand: `make build-setup-deploy` 
<br>↓ following steps are invoked by the above `make` command automatically ↓<br>
* use `./Makefile`
    * invoke `./Makefile` target: `build-setup-deploy`
      * invoke `./Makefile` targets: `sandbox-*-docker` (sandbox docker containers build)
      * use `./k8s/Makefile`
        * invoke `./k8s/Makefile` target: `local-setup-deploy`
          * invoke `./k8s/Makefile` target: `minikube-down`
          * invoke `./k8s/Makefile` target: `minikube-up`
            * invoke `./k8s/Makefile` target: `pull-core-deployment`
              * run script `./k8s/scripts/core_deployment.sh` 
                * clone github repo: `trustbloc/k8s` into dir `./k8s/.core` (commit id `TRUSTBLOC_CORE_K8S_COMMIT` set in `./Makefile`)  
                * OR symlink dir `./k8s/.core` to a local dir (if enabled in `./k8s/scripts/core_deployment.sh`)
            * run script `./k8s/scripts/minikube_setup.sh`
              * creates minikube cluster
              * update `/etc/hosts`
          * invoke `./k8s/Makefile` target: `minikube-image-load`
          * invoke `./k8s/Makefile` target: `deploy-core`
          * use `./k8s/.core/Makefile`
            * invoke `./k8s/.core/Makefile` target: `deploy-all`
              * run script: `./k8s/.core/scripts/deploy_all.sh`
                * invoke `./k8s/.core/dbs/Makefile` target: default (`deploy`)
                  * setup (download) kustomize
                  * kustomize: set-images, set-labels
                  * minikube image load
                  * deploy dbs: (`kustomize build | kubectl apply`)
                * setup (create) certificates in `~/.trustbloc-k8s/`
                * [ iterate over core $COMPONENTS list ]
                  * invoke `./k8s/.core/$COMPONENT/Makefile` target: `setup-no-certs`                
                  * put certificate files into `./k8s/.core/$COMPONENT/kustomize/$COMPONENT/overlays/$DEPLOYMENT_ENV/certs`                
                  * invoke `./k8s/.core/$COMPONENT/Makefile` target: `deploy`
                    * setup (download) kustomize
                    * kustomize: set-images, set-labels
                    * minikube image load
                    * deploy $COMPONENT (`kustomize build | kubectl apply`)
                  * run health-check for $COMPONENT
          * run script: `./k8s/scripts/deploy_all.sh`
            * [ iterate over sandbox $COMPONENTS list ]
              * invoke `./k8s/$COMPONENT/Makefile` target: `setup-no-certs`
              * put certificate files into `./k8s/$COMPONENT/kustomize/$COMPONENT/overlays/$DEPLOYMENT_ENV/certs`       
              * invoke `./k8s/$COMPONENT/Makefile` target: `deploy`
                * setup (download) kustomize
                * kustomize: set-images, set-labels
                * minikube image load
                * deploy $COMPONENT (`kustomize build | kubectl apply`)
              * run health-check for $COMPONENT

## Kustomize hierarchy
Kustomize uses *base* as the component's configuration common part for all environments:
* `./k8s/$COMPONENT/kustomize/$COMPONENT/base`
* `./k8s/.core/$COMPONENT/kustomize/$COMPONENT/base`

Local deployment's specific customisation is stored under the *local* overlay:
* `./k8s/$COMPONENT/kustomize/$COMPONENT/overlays/local/$COMPONENT`
* `./k8s/.core/$COMPONENT/kustomize/$COMPONENT/overlays/local/$COMPONENT`