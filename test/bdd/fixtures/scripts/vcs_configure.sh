#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# CouchDB takes time to start up, so we will retry if trying to create a profile fails




n=0
maxAttempts=30
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-1", "uri":"http://vc-issuer-1.com", "signatureType":"Ed25519Signature2018", "signatureRepresentation":1}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer1 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer1 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."

   n=$((n+1))
   sleep 5
done


n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-2", "uri":"http://vc-issuer-2.com", "signatureType":"Ed25519Signature2018", "did":"did:v1:test:nym:z6MkiJFtehU8FcTu6hAKiBEzzD5LfZHRR9wiiyJCgkbCZ6XN","didPrivateKey":"4Gn9Ttw6Lf3oFBFqJNNdLFMc4mUbbpCYLNSQFGAxaLBXiJ6DuZpJ8qsZGaHqwyBptxJMEB8nFiqHDZ419XHHxudY","signatureRepresentation":0}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer2 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer2 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done

n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-3", "uri":"http://vc-issuer-3.com", "signatureType":"Ed25519Signature2018", "did":"did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ","didPrivateKey":"5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR","signatureRepresentation":0}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer3 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer3 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done

n=0
maxAttempts=20
until [ $n -ge $maxAttempts ]
do
   responseCreatedTime=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"name":"vc-issuer-4", "uri":"http://vc-issuer-4.com", "signatureType":"Ed25519Signature2018", "did":"did:sov:danube:CDEabPCipwE51bg7KF9yXt","didPrivateKey":"22WXAJuENXAZUKZuRceBP3S6G5mrbah9WvNxRan23HvLZ7kHMBMvZoAqAwbBo9WhkYdKVa11cCySH9m2HRmFXeaq","signatureRepresentation":0}' \
   http://issuer.vcs.example.com:8070/profile | jq -r '.created' 2>/dev/null)
   echo "'created' field from profile issuer4 response is: $responseCreatedTime"

   if [ -n "$responseCreatedTime" ]
   then
      break
   fi
   echo "Invalid 'created' field from issuer4 response when trying to create a profile (attempt $((n+1))/$maxAttempts)."
   n=$((n+1))
   sleep 5
done
