# [TrustBloc Sandbox Shared DBs]() k8s deployment #


## pre-requisits
* [Minikube](https://minikube.sigs.k8s.io/docs/start/).
* (Optional: Gets installed by make) [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/).

## Quick Run
* `make all`
* `make deploy-sandbox`

## Cleanup
* `make undeploy-sandbox`
* `make clean`

## options and features
* Will deploy Sandbox MongoDB and MySQL.
