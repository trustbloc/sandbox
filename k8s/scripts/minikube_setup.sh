# 
# Copyright SecureKey Technologies Inc. All Rights Reserved. 
# 
# SPDX-License-Identifier: Apache-2.0 
# 

#!/usr/bin/env bash

# Set default values, which may be overriden by the environment variables
: ${DOMAIN:=trustbloc.dev}
: ${MEMORY:=6g}
: ${CPUS:=4}
: ${ADDONS:=ingress,ingress-dns,dashboard}

PATCH=.ingress_coredns.patch

# List of services used to generate domain names
SERVICES=$( cat service_list.txt )
OS=$( uname -s | tr '[:upper:]' '[:lower:]' )

# Use specified driver if set, otherwise minikube will auto-detect the best default driver for a given platform
if [[ -n $DRIVER ]]; then
    DRIVER="--driver=$DRIVER"
else
    # MacOS requires hyperkit driver instead of the auto-detected for compatibility with ingress addon
    if [[ $OS == darwin ]]; then
        DRIVER='--driver=hyperkit'
    fi
fi

minikube start --memory=$MEMORY --cpus=$CPUS --addons=$ADDONS $DRIVER $MINIKUBE_OPTIONS
MINIKUBE_IP=$( minikube ip )

# Patch coredns configMap
if ! kubectl get cm coredns -n kube-system -o yaml | grep -q hosts; then
    # Generate coredns configMap patch
    echo '        hosts {' > $PATCH
    for service in $SERVICES; do
        echo "          $MINIKUBE_IP $service.$DOMAIN" >> $PATCH
    done
    echo '          fallthrough' >> $PATCH
    echo '        }' >> $PATCH

    echo 'Patching coredns ConfigMap'
    EDITOR='sed -i "/loadbalance/r.ingress_coredns.patch"' kubectl edit cm coredns -n kube-system
    kubectl delete po -l k8s-app=kube-dns -n kube-system # apply new configmap changes
else
    # Generate coredns configMap patch
    rm $PATCH
    for service in $SERVICES; do
        echo "           $MINIKUBE_IP $service.$DOMAIN" >> $PATCH
    done

    echo 'Patching coredns ConfigMap'
    EDITOR='sed -i "/hosts {/r.ingress_coredns.patch"' kubectl edit cm coredns -n kube-system
    kubectl delete po -l k8s-app=kube-dns -n kube-system # apply new configmap changes
fi

echo '!!! Make sure you have these entries added to your /etc/hosts !!!'
echo '=========================== CUT =========================='
for service in $SERVICES; do
    echo "$MINIKUBE_IP $service.$DOMAIN"
done
echo '=========================== CUT =========================='
