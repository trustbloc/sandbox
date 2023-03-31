#!/bin/sh -xe
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Adding curl and jq"
apk --no-cache add curl jq

# If necessary, convert the reported architecture name to the (equivalent) names that are used in the kubectl binary
# filenames.
ARCH=$( uname -m)
case $ARCH in
   x86_64)
     ARCH="amd64"
     ;;
   aarch64)
     ARCH="arm64"
     ;;
esac

echo
echo "fetching kubectl"
curl -qL https://storage.googleapis.com/kubernetes-release/release/v1.25.8/bin/linux/$ARCH/kubectl -o /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl

token=TOKEN

mkdir -p /oathkeeper/rules
sed -e "s/{TOKEN}/$token/g" /oathkeeper/template/access-rules.tmpl > /oathkeeper/rules/access-rules.json

echo
config_map=$(kubectl get cm  -l component=cms  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep oathkeeper-rules)
echo "mutating oathkeeper configMap ${config_map}"
kubectl create cm ${config_map} --dry-run=client --from-file=/oathkeeper/rules/access-rules.json -o yaml | kubectl apply -f -
echo "labeling"
kubectl label cm ${config_map} component=cms group=demo project=trustbloc instance=||DEPLOYMENT_ENV||
echo "Finished processing template"
