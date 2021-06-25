#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

## Run minikube setup before the local deployment
# bash minikube_setup.sh

## Default values, will be overriden by the existing env variable value
: ${DOMAIN:=trustbloc.dev}
: ${DEPLOYMENT_ENV:=local}
## Should be deployed in the listed order
: ${COMPONENTS=cms comparator login-consent issuer rp ace-rp jobs}
DEPLOY_LIST=( $COMPONENTS )

## Map: component --> healthcheck(s)
declare -A HEALTCHECK_URL=(
    [cms]=""
    [comparator]="https://ucis-comparator.$DOMAIN/healthcheck https://cbp-comparator.$DOMAIN/healthcheck https://benefits-dept-comparator.$DOMAIN/healthcheck"
    [issuer]="https://demo-issuer.$DOMAIN/healthcheck"
    [rp]="https://demo-rp.$DOMAIN/healthcheck"
    [ace-rp]="https://ucis-rp.$DOMAIN/healthcheck https://cbp-rp.$DOMAIN/healthcheck https://benefits-dept-rp.$DOMAIN/healthcheck"
    [login-consent]=""
    [jobs]=""
    [LATE]="https://cms.$DOMAIN/"
)
## Map: healthckeck --> http-code
declare -A HEALTHCHECK_CODE=(
    [https://ucis-comparator.$DOMAIN/healthcheck]=200
    [https://cbp-comparator.$DOMAIN/healthcheck]=200
    [https://benefits-dept-comparator.$DOMAIN/healthcheck]=200
    [https://demo-rp.$DOMAIN/healthcheck]=200
    [https://demo-issuer.$DOMAIN/healthcheck]=200
    [https://ucis-rp.$DOMAIN/healthcheck]=200
    [https://cbp-rp.$DOMAIN/healthcheck]=200
    [https://benefits-dept-rp.$DOMAIN/healthcheck]=200
    [https://cms.$DOMAIN/]=200
)

# healthCheck function -- copied from sandbox
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
AQUA=$(tput setaf 6)
NONE=$(tput sgr0)
healthCheck() {
	sleep 2
	n=0
  maxAttempts=200
  if [ "" != "$4" ]
  then
	   maxAttempts=$4
  fi
	echo "running health check : app=$1 url=$2 timeout=$maxAttempts seconds"
	until [ $n -ge $maxAttempts ]
	do
	  response=$(curl -H 'Cache-Control: no-cache' -o /dev/null -s -w "%{http_code}" --insecure "$2")
	   if [ "$response" == "$3" ]
	   then
		 echo "${GREEN}$1 $2 is up ${NONE}"
		 break
	   fi
	   n=$((n+1))
	   if [ $n -eq $maxAttempts ]
	   then
		 echo "${RED}failed health check : app=$1 url=$2 responseCode=$response ${NONE}"
	   fi
	   sleep 1
	done
}

## deploy the DBs dependency first
pushd demo-dbs
    make SHELL=/bin/bash
popd
### TODO: set up proper mysql, couchDB healthchecks
echo wait for DBs to start up
while [[ `kubectl get po | grep Running |wc -l` -lt 2 ]]; do
    sleep 1
done
# healthCheck couchdb $couchdbHealthCheckURL 200
# checkMYSQLDB strapi
# checkMYSQLDB rpadapter_hydra
# checkMYSQLDB authresthydra
# checkMYSQLDB edgeagent_aries

root=$(pwd)
echo "$root"

## generate certificate for all components, skip if already exists
if ! [[ -d ~/.trustbloc-k8s/${DEPLOYMENT_ENV}/certs ]]; then
pushd ./.core/orb
    cp -r kustomize/orb/overlays/${DEPLOYMENT_ENV}/certs ~/.trustbloc-k8s/${DEPLOYMENT_ENV}/
popd
fi

for component in ${DEPLOY_LIST[@]}; do
    echo "${AQUA} === component: $component ${NONE}"
    pushd $component
        make SHELL=/bin/bash setup-no-certs
        mkdir -p kustomize/$component/overlays/${DEPLOYMENT_ENV}/certs
        cp ~/.trustbloc-k8s/${DEPLOYMENT_ENV}/certs/* kustomize/$component/overlays/${DEPLOYMENT_ENV}/certs
        make SHELL=/bin/bash deploy
    popd
    ## run all health checks for a given component
    for url in ${HEALTCHECK_URL[$component]}; do
        healthCheck $component "$url" ${HEALTHCHECK_CODE["$url"]}
    done
#    echo press ENTER to continue && read L
done

## Late health checks
component=LATE
for url in ${HEALTCHECK_URL[$component]}; do
    healthCheck $component "$url" ${HEALTHCHECK_CODE["$url"]} 600
done
