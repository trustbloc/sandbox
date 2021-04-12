# [Demo Applications](https://github.com/trustbloc/sandbox) k8s deployment #


## pre-requisits
* [Minikube](https://minikube.sigs.k8s.io/docs/start/) with ingress addon.
* GNU sed
* (Optional: Gets installed by make) [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/).

## Quick Run
* `make all`
* `make deploy-rp`

## Cleanup
* `make undeploy-rp`
* `make clean`

## options and features
* By default dns domain is `trustboc.dev`. To run with different domain (See next), run with: `make DOMAIN=ali.trustbloc.dev`
* Will create an Ingress for external access. When running with unregistered dns domains, create records (/etc/hosts) for:
	- `rp.DOMAIN`
* Will deploy Sandbox Demo Applications, pointing to an already provisioned COUCHDB specified with `COUCHDB_URL`
	- `make deploy COUCHDB_URL=couchdb://cdbadmin:secret@couchdb:5984`
* if running `podman` pass `CONTAINER_CMD=podman` as option to make
* Running with none self-signed certificates: place certs into kustomize/demo-applications/overlays/sandbox/certs, then run with: `make setup-no-certs`.
>files:
	- ca.crt
	- tls.crt
	- tls.key

## Known issues
* RP fails to start without VCS connectivity.
