# [Comparator](https://github.com/trustbloc/edge-service/blob/f48851fa0210c74fcf3a4c7569ac8eaded1794f8/cmd/comparator-rest/README.md) k8s deployment #


## pre-requisits
* [Minikube](https://minikube.sigs.k8s.io/docs/start/) with ingress addon.
* GNU sed
* (Optional: Gets installed by make) [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/).

## Quick Run
* `make all`
* `make deploy-sandbox`

## Cleanup
* `make undeploy-sandbox`
* `make clean`

## options and features
* By default dns domain is `local.trustboc.dev`. To run with different domain (See next), run with: `make DOMAIN=ali.trustbloc.dev`
* By default Bloc domain is `orb-1.local.trustboc.dev`. To run with different domain (See next), run with: `make BLOC_DOMAIN=orb-1.ali.trustbloc.dev`
* Will create an Ingress for external access. When running with unregistered dns domains, create records (/etc/hosts) for:
	- `benefits-dept-comparator.DOMAIN`
	- `cbp-comparator.DOMAIN`
	- `ucis-comparator.DOMAIN`
* Will deploy Sandbox Comparator, pointing to an already provisioned COUCHDB specified with `COUCHDB_DSN`
	- `make deploy COUCHDB_DSN=couchdb://cdbadmin:secret@couchdb:5984`
* if running `podman` pass `CONTAINER_CMD=podman` as option to make
* Running with none self-signed certificates: place certs into kustomize/comparator/overlays/sandbox/certs, then run with: `make setup-no-certs`.
>files:
	- ca.crt
	- tls.crt
	- tls.key

## Known issues
* comparator sandbox overlays will fail if csh.DOMAIN (hubstore)
is not reachable
