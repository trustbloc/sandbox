#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

PATCH=.ingress_coredns.patch
COREDNS_CM=.coredns.bak.json

# List of services used to generate domain names
mapfile -t SERVICES < service_list.txt

MINIKUBE_IP=$( minikube ip )

generate_host_entries() {
    for service in ${SERVICES[@]}; do
        echo "$1$MINIKUBE_IP $service.$DOMAIN"
    done
}

# Patch coredns configMap
echo 'Patching coredns configMap (adding custom service entries to the hosts section)...'
kubectl get cm coredns -n kube-system -o json > $COREDNS_CM
if ! grep -q hosts $COREDNS_CM; then
    echo 'hosts section does not exist, adding it'

    # Generate coredns configMap patch
    echo '        hosts {' > $PATCH
    generate_host_entries '          ' >> $PATCH
    echo '          fallthrough' >> $PATCH
    echo '        }' >> $PATCH

    EDITOR='sed -i "/loadbalance/r.ingress_coredns.patch"' kubectl edit cm coredns -n kube-system
else
    echo 'hosts section already exists, patching it'

    # Generate new Corefile for replacement
    kubectl get cm coredns -n kube-system -o jsonpath='{.data}' | jq -r '.Corefile' > Corefile.config
    HOSTS_START_LINE=$( grep -n 'hosts {' Corefile.config | cut -d : -f 1 )
    head -$HOSTS_START_LINE Corefile.config > $PATCH
    generate_host_entries '       ' >> $PATCH
    tail +$(( HOSTS_START_LINE + 1 )) Corefile.config >> $PATCH

    echo '=== listing the patched Corefile ==='
    cat $PATCH
    echo '=== end patched Corefile listing ==='

    jq --arg replace "`cat $PATCH`" '.data.Corefile = $replace' $COREDNS_CM | kubectl apply -f -
fi
echo 'Running kubectl rollout restart for coredns...'
kubectl rollout restart deployment/coredns -n kube-system
echo 'Verifying that DNS resolution works inside the cluster'
DNS_CHECK_SCRIPT="for svc in ${SERVICES[*]}; do echo Checking DNS for \$svc...; host \$svc.$DOMAIN | grep \$svc.$DOMAIN; done"
if ! kubectl run dnsutils --image=gcr.io/kubernetes-e2e-test-images/dnsutils:1.3 --rm --attach --command --restart=Never -- sh -ec "$DNS_CHECK_SCRIPT"; then
    echo 'DNS resolution test failed, rolling back the coreDNS configMap'
    kubectl apply -f $COREDNS_CM -n kube-system
    kubectl rollout undo deployment/coredns -n kube-system
    exit 11
else
    echo 'Done patching coreDNS configMap'
fi
