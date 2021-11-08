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

# Patch coredns configMap
echo 'Patching coredns configMap (adding custom service entries to the hosts section)...'
if ! kubectl get cm coredns -n kube-system -o yaml | grep -q hosts; then
    echo 'hosts section does not exist, adding it'

    # Generate coredns configMap patch
    echo '        hosts {' > $PATCH
    for service in $SERVICES; do
        echo "          $MINIKUBE_IP $service.$DOMAIN" >> $PATCH
    done
    echo '          fallthrough' >> $PATCH
    echo '        }' >> $PATCH

    EDITOR='sed -i "/loadbalance/r.ingress_coredns.patch"' kubectl edit cm coredns -n kube-system
else
    echo 'hosts section already exists, patching it'

    # Generate new Corefile for replacement
    kubectl get cm coredns -n kube-system -o jsonpath='{.data}' | jq -r '.Corefile' > Corefile.config
    HOSTS_START_LINE=$( grep -n 'hosts {' Corefile.config | cut -d : -f 1 )
    head -$HOSTS_START_LINE Corefile.config > $PATCH
    for service in $SERVICES; do
        echo "       $MINIKUBE_IP $service.$DOMAIN" >> $PATCH
    done
    tail +$(( HOSTS_START_LINE + 1 )) Corefile.config >> $PATCH

    echo '=== listing the patched Corefile ==='
    cat $PATCH
    echo '=== end patched Corefile listing ==='

    kubectl get cm coredns -n kube-system -o json | jq --arg replace "`cat $PATCH`" '.data.Corefile = $replace' | kubectl apply -f -
fi
echo 'Restarting coredns pod to apply the patch'
kubectl delete po -l k8s-app=kube-dns -n kube-system
echo 'Done patching coreDNS configMap'

echo 'updating entries in /etc/hosts'
echo '=========================== CUT =========================='
for service in $SERVICES; do
    sudo echo "$MINIKUBE_IP $service.$DOMAIN" | sudo tee -a /etc/hosts
done
echo '=========================== CUT =========================='
