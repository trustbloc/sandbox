#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)

couchdbUser=cdbadmin
couchdbPassword=secret

mysqlUser=root
mysqlPassword=secret

couchdbHealthCheckURL=http://$couchdbUser:$couchdbPassword@shared.couchdb:5984
sidetreeDiscovery=https://testnet.trustbloc.local/.well-known/did-trustbloc/testnet.trustbloc.local.json
edvHealthCheckURL=https://edv-oathkeeper-proxy.trustbloc.local/healthcheck
resolverHealthCheckURL=https://did-resolver.trustbloc.local/1.0/identifiers/did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A
registrarHealthCheckURL=https://uni-registrar-web.trustbloc.local/1.0/register
didMethodHealthCheckURL=https://did-method.trustbloc.local/healthcheck
issuerVCSHealthCheckURL=https://issuer-vcs.trustbloc.local/healthcheck
rpVCSHealthCheckURL=https://rp-vcs.trustbloc.local/healthcheck
holderVCSHealthCheckURL=https://holder-vcs.trustbloc.local/healthcheck
governanceVCSHealthCheckURL=https://governance-vcs.trustbloc.local/healthcheck
authzKMSHealthCheckURL=https://oathkeeper-auth-keyserver.trustbloc.local/healthcheck
opsKMSHealthCheckURL=https://oathkeeper-ops-keyserver.trustbloc.local/healthcheck
authHealthCheckURL=https://auth-rest.trustbloc.local/healthcheck
routerHealthCheckURL=https://router.trustbloc.local:9084/healthcheck
walletHealthCheckURL=https://myagent.trustbloc.local/login
rpAdapterHealthCheckURL=https://rp-adapter.trustbloc.local:10161/healthcheck
issuerAdapterHealthCheckURL=https://issuer-adapter.trustbloc.local:10061/healthcheck
rpHealthCheckURL=https://rp.trustbloc.local/bankaccount
issuerHealthCheckURL=https://issuer.trustbloc.local/drivinglicense
acRpHealthCheckURL=https://acrp.trustbloc.local
cmsHealthCheckURL=https://cms.trustbloc.local/
sidetreePeer=https://sidetree-mock.trustbloc.local

checkMYSQLDB()
{
n=0
maxAttempts=60
echo "check mysql db '$1' exist please wait for max $maxAttempts seconds"


until [ $n -ge $maxAttempts ]
do

  response=$(docker exec  -e MYSQL_PWD=$mysqlPassword mysql  mysql --user=$mysqlUser -e "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$1'" 2>&1)

  if [[ $response == *"$1"* ]]
  then
     echo "${GREEN}$1 db is exist"
     tput sgr0
     break
   fi

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "${RED}$1 db is not exist"
     tput sgr0
     exit -1
   fi
   sleep 1

done
}

healthCheck()
{
# TODO need to add nginx conf
# for now we wait until nginx pick up the VIRTUAL_HOST
sleep 3
n=0
maxAttempts=200
echo "health check for $1 url $2 please wait for max $maxAttempts seconds"


until [ $n -ge $maxAttempts ]
do
  response=$(curl -H 'Cache-Control: no-cache' -o /dev/null -s -w "%{http_code}" --insecure "$2")
   if [ "$response" == "$3" ]
   then
     echo "${GREEN}$1 is up"
     tput sgr0
     break
   fi

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "${RED}failed health check for $1 url $2 response code $response"
     tput sgr0
     exit -1
   fi
   sleep 1

done

}


pingHost()
{
# TODO need to add nginx conf
# for now we wait until nginx pick up the VIRTUAL_HOST
sleep 3
n=0
maxAttempts=120
echo "ping for $1 host $2 port $3 please wait for max $maxAttempts seconds"


until [ $n -ge $maxAttempts ]
do

   nc -z -v -w 5 "$2" "$3" &> /dev/null
   result=$?

   if [ "$result" == 0  ]
   then
     echo "${GREEN}$1 is up"
     tput sgr0
     break
   fi

   n=$((n+1))
   if [ $n -eq $maxAttempts ]
   then
     echo "${RED}failed ping for $1 host $2 port $3"
     tput sgr0
     exit -1
   fi
   sleep 1

done

}


generateDIDMethodConfigMock(){
echo "generate did-method config"

.build/did-method-cli/cli create-config --sidetree-url https://sidetree-mock.trustbloc.local/sidetree/0.0.1 \
--tls-cacerts ./test/bdd/fixtures/keys/tls/trustbloc-dev-ca.crt --sidetree-write-token rw_token \
--recoverykey-file ./test/bdd/fixtures/keys/recover/public.pem --updatekey-file ./test/bdd/fixtures/keys/update/public.pem \
--config-file ./test/bdd/fixtures/discovery-config/sidetree-mock/config-data/testnet.trustbloc.local.json --output-directory ./test/bdd/fixtures/discovery-config/sidetree-mock/temp


rm -rf ./test/bdd/fixtures/discovery-config/sidetree-mock/config
mkdir -p ./test/bdd/fixtures/discovery-config/sidetree-mock/config/did-trustbloc
cp ./test/bdd/fixtures/discovery-config/sidetree-mock/temp/did-trustbloc/* ./test/bdd/fixtures/discovery-config/sidetree-mock/config/did-trustbloc
cp ./test/bdd/fixtures/discovery-config/sidetree-mock/temp/stakeholder-one.trustbloc.local/did-configuration.json ./test/bdd/fixtures/discovery-config/sidetree-mock/config

# TODO: this mkdir and copy are needed after config files are generated for sidetree-fabric as well
mkdir -p ./test/bdd/fixtures/discovery-config/genesis-configs
cp ./test/bdd/fixtures/discovery-config/sidetree-mock/temp/did-trustbloc/testnet.trustbloc.local.json ./test/bdd/fixtures/discovery-config/genesis-configs

rm -rf ./test/bdd/fixtures/discovery-config/sidetree-mock/temp

echo "${GREEN}create did-method config successfully"
tput sgr0
}


scripts/sandbox_stop.sh


### Step 1
echo "#### Step 1 start demo db's"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-dbs.yml down && docker-compose -f docker-compose-dbs.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck couchdb $couchdbHealthCheckURL 200
checkMYSQLDB strapi
checkMYSQLDB rpadapter_hydra
checkMYSQLDB authresthydra
checkMYSQLDB edgeagent_aries
echo "#### Step 1 is complete"
###

# need to start cms here because will take long time to start will check status later in script
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-cms.yml down && docker-compose -f docker-compose-cms.yml up --force-recreate) > docker.log 2>&1 & )

### Step 2
echo "#### Step 2 start demo sidetree"
if [ "$START_SIDETREE_FABRIC" = true ] ; then
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-sidetree-fabric.yml down && docker-compose -f docker-compose-sidetree-fabric.yml up --force-recreate) > docker.log 2>&1 & )
pingHost peer localhost 7051
(cd test/bdd && go test)
else
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-sidetree-mock.yml down && docker-compose -f docker-compose-sidetree-mock.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck sidetree $sidetreePeer 404
generateDIDMethodConfigMock
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-sidetree-mock-discovery.yml down && docker-compose -f docker-compose-sidetree-mock-discovery.yml up --force-recreate) > docker.log 2>&1 & )
fi
healthCheck sidetree-discovery $sidetreeDiscovery 200
echo "#### Step 2 is complete"
###
### Step 3
echo "#### Step 3 start demo edv"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-edv.yml down && docker-compose -f docker-compose-edv.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck edv $edvHealthCheckURL 200
echo "#### Step 3 is complete"
###
### Step 4
echo "#### Step 4 start demo resolver"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-resolver.yml down && docker-compose -f docker-compose-resolver.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck resolver $resolverHealthCheckURL 200
echo "#### Step 4 is complete"
###
### Step 5
echo "#### Step 5 start demo registrar"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-registrar.yml down && docker-compose -f docker-compose-registrar.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck registrar $registrarHealthCheckURL 405
echo "#### Step 5 is complete"
###
### Step 6
echo "#### Step 6 start trustbloc-did-method"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-did-method.yml down && docker-compose -f docker-compose-did-method.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck did-method $didMethodHealthCheckURL 200
echo "#### Step 6 is complete"
###
### Step 7
echo "#### Step 7 start demo vcs"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-vcs.yml down && docker-compose -f docker-compose-vcs.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck issuerVCS $issuerVCSHealthCheckURL 200
healthCheck rpVCS $rpVCSHealthCheckURL 200
healthCheck holderVCS $holderVCSHealthCheckURL 200
healthCheck governanceVCS $governanceVCSHealthCheckURL 200
if ! test/bdd/fixtures/scripts/vcs_issuer_configure.sh; then
  exit -1
fi
if ! test/bdd/fixtures/scripts/vcs_verifier_configure.sh; then
   exit -1
fi
if ! test/bdd/fixtures/scripts/vcs_holder_configure.sh; then
   exit -1
fi
if ! test/bdd/fixtures/scripts/vcs_governance_configure.sh; then
   exit -1
fi
echo "#### Step 7 is complete"
###
### Step 8
echo "#### Step 8 start demo kms"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-kms.yml down && docker-compose -f docker-compose-kms.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck authz-kms $authzKMSHealthCheckURL 200
healthCheck ops-kms $opsKMSHealthCheckURL 200
echo "#### Step 8 is complete"
###
### Step 9
echo "#### Step 9 start demo auth"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-auth.yml down && docker-compose -f docker-compose-auth.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck auth $authHealthCheckURL 200
echo "#### Step 9 is complete"
###
### Step 10
echo "#### Step 10 start demo wallet"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-wallet.yml down && docker-compose -f docker-compose-wallet.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck router $routerHealthCheckURL 200
healthCheck wallet $walletHealthCheckURL 200
echo "#### Step 10 is complete"
###
### Step 11
echo "#### Step 11 start demo adapter"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-adapter.yml down && docker-compose -f docker-compose-adapter.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck issuerAdapter $issuerAdapterHealthCheckURL 200
healthCheck rpAdapter $rpAdapterHealthCheckURL 200
echo "#### Step 11 is complete"
###
### Step 12
echo "#### Step 12 start demo application"
(cd test/bdd/fixtures/demo; (docker-compose -f docker-compose-demo-applications.yml down && docker-compose -f docker-compose-demo-applications.yml up --force-recreate) > docker.log 2>&1 & )
healthCheck issuer $issuerHealthCheckURL 200
healthCheck rp $rpHealthCheckURL 200
healthCheck acrp $acRpHealthCheckURL 200
echo "#### Step 12 is complete"
###
### Step 13
echo "#### Step 13 start demo cms"
# cms already started will do health check
healthCheck cms $cmsHealthCheckURL 200
echo "#### Step 13 is complete"
###
