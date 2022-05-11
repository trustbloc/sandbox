# [Gatekeeper](https://github.com/trustbloc/ace#gatekeeper) k8s deployment

## Prerequisites
* [Minikube](https://minikube.sigs.k8s.io/docs/start/) with ingress addon.
* GNU sed
* (Optional: Gets installed by make) [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/).

## Quick Run
* `make all`
* `make deploy-gatekeeper`

## Cleanup
* `make undeploy-gatekeeper`
* `make clean`
