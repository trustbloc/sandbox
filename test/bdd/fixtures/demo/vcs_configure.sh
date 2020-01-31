#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl

curl -d '{"name":"demo", "did":"did:demo:abc", "uri":"http://demo.com", "signatureType":"Ed25519Signature2018", "creator":"did:demo:abc#key1" }' -H "Content-Type: application/json" -X POST http://vcs.example.com:8070/profile
