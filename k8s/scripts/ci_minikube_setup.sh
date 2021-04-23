#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

#!/usr/bin/env bash

# Set default values, which may be overriden by the environment variables
: ${DOMAIN:=trustbloc.dev}

PATCH=.ingress_coredns.patch

# List of services used to generate domain names
SERVICES=$( cat service_list.txt )
OS=$( uname -s | tr '[:upper:]' '[:lower:]' )

MINIKUBE_IP=$( minikube ip )

# Generate coredns configMap patch
echo '        hosts {' > $PATCH
for service in $SERVICES; do
    echo "          $MINIKUBE_IP $service.$DOMAIN" >> $PATCH
done
echo '          fallthrough' >> $PATCH
echo '        }' >> $PATCH

# Patch coredns configMap
if ! kubectl get cm coredns -n kube-system -o yaml | grep -q hosts; then
    echo 'Patching coredns ConfigMap'
    EDITOR='sed -i "/loadbalance/r.ingress_coredns.patch"' kubectl edit cm coredns -n kube-system
    kubectl delete po -l k8s-app=kube-dns -n kube-system # apply new configmap changes
else
    echo 'Skipping coredns ConfigMap patch because it has already been patched. Please patch it manually to add any new entries.'
fi

echo 'updating entries in /etc/hosts'
echo '=========================== CUT =========================='
for service in $SERVICES; do
    sudo echo "$MINIKUBE_IP $service.$DOMAIN" | sudo tee -a /etc/hosts
done
echo '=========================== CUT =========================='
