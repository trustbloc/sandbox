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
: ${COMPONENTS=cms comparator login-consent hub-auth demo-applications}
DEPLOY_LIST=( $COMPONENTS )

## Map: component --> healthcheck(s)
declare -A HEALTCHECK_URL=(
    [sidetree-mock]="https://sidetree-mock.$DOMAIN https://testnet.$DOMAIN/.well-known/did-trustbloc/testnet.$DOMAIN.json"
    [cms]=""
    [edv]="https://edv-oathkeeper-proxy.$DOMAIN/healthcheck"
    [resolver]="https://did-resolver.$DOMAIN/1.0/identifiers/did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
    [registrar]="https://uni-registrar-web.$DOMAIN/1.0/register"
    [did-method]="https://did-method.$DOMAIN/healthcheck"
    [csh]="https://csh.$DOMAIN/healthcheck"
    [vcs]="https://issuer-vcs.$DOMAIN/healthcheck https://rp-vcs.$DOMAIN/healthcheck https://rp-vcs.$DOMAIN/healthcheck https://governance-vcs.$DOMAIN/healthcheck"
    [vault-server]="https://vault-server.$DOMAIN/healthcheck"
    [comparator]="https://ucis-comparator.$DOMAIN/healthcheck https://cbp-comparator.$DOMAIN/healthcheck https://benefits-dept-comparator.$DOMAIN/healthcheck"
    [kms]="https://authz-oathkeeper-proxy.$DOMAIN/healthcheck https://ops-oathkeeper-proxy.$DOMAIN/healthcheck https://vault-kms.$DOMAIN/healthcheck"
    [hub-auth]="https://hub-auth.$DOMAIN/healthcheck"
    [wallet]="https://router-api.$DOMAIN:9084/healthcheck https://myagent.$DOMAIN/login"
    [wallet]="https://myagent.$DOMAIN/login"
    [adapters]="https://adapter-rp.$DOMAIN/healthcheck https://adapter-issuer.$DOMAIN/healthcheck"
    [demo-applications]="https://issuer.$DOMAIN/drivinglicense https://rp.$DOMAIN/bankaccount https://ucis-rp.$DOMAIN https://cbp-rp.$DOMAIN https://benefits-dept-rp.$DOMAIN"
    [login-consent]=""
    [fabric]=""
    [LATE]="https://cms.$DOMAIN/"
)
## Map: healthckeck --> http-code
declare -A HEALTHCHECK_CODE=(
    [http://localhost:45984]=200
    [https://testnet.$DOMAIN/.well-known/did-trustbloc/testnet.$DOMAIN.json]=200
    [https://sidetree-mock.$DOMAIN]=404
    [https://edv-oathkeeper-proxy.$DOMAIN/healthcheck]=200
    [https://did-resolver.$DOMAIN/1.0/identifiers/did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A]=200
    [https://uni-registrar-web.$DOMAIN/1.0/register]=405
    [https://did-method.$DOMAIN/healthcheck]=200
    [https://issuer-vcs.$DOMAIN/healthcheck]=200
    [https://rp-vcs.$DOMAIN/healthcheck]=200
    [https://holder-vcs.$DOMAIN/healthcheck]=200
    [https://governance-vcs.$DOMAIN/healthcheck]=200
    [https://ucis-comparator.$DOMAIN/healthcheck]=200
    [https://cbp-comparator.$DOMAIN/healthcheck]=200
    [https://benefits-dept-comparator.$DOMAIN/healthcheck]=200
    [https://vault-server.$DOMAIN/healthcheck]=200
    [https://csh.$DOMAIN/healthcheck]=200
    [https://authz-oathkeeper-proxy.$DOMAIN/healthcheck]=200
    [https://ops-oathkeeper-proxy.$DOMAIN/healthcheck]=200
    [https://vault-kms.$DOMAIN/healthcheck]=200
    [https://hub-auth.$DOMAIN/healthcheck]=200
    [https://router-api.$DOMAIN:9084/healthcheck]=200
    [https://myagent.$DOMAIN/login]=200
    [https://adapter-rp.$DOMAIN/healthcheck]=200
    [https://adapter-issuer.$DOMAIN/healthcheck]=200
    [https://rp.$DOMAIN/bankaccount]=200
    [https://issuer.$DOMAIN/drivinglicense]=200
    [https://ucis-rp.$DOMAIN]=200
    [https://cbp-rp.$DOMAIN]=200
    [https://benefits-dept-rp.$DOMAIN]=200
    [https://cms.$DOMAIN/]=200
)

# healthCheck function -- copied from sandbox
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
AQUA=$(tput setaf 6)
NONE=$(tput sgr0)
healthCheck()
{
sleep 3
n=0
maxAttempts=200
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
pushd dbs
    make
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
pushd ./.core/sidetree-mock
    cp -r kustomize/sidetree-mock/overlays/${DEPLOYMENT_ENV}/certs ~/.trustbloc-k8s/${DEPLOYMENT_ENV}/
popd
fi

for component in ${DEPLOY_LIST[@]}; do
    echo "${AQUA} === component: $component ${NONE}"
    pushd $component
        make setup-no-certs
        mkdir -p kustomize/$component/overlays/${DEPLOYMENT_ENV}/certs
        cp ~/.trustbloc-k8s/${DEPLOYMENT_ENV}/certs/* kustomize/$component/overlays/${DEPLOYMENT_ENV}/certs
        make deploy
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
    healthCheck $component "$url" ${HEALTHCHECK_CODE["$url"]}
done
