#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl

curl -d '{"name":"vc-issuer-1", "uri":"http://vc-issuer-1.com", "signatureType":"Ed25519Signature2018"}' -H "Content-Type: application/json" -X POST http://vcs.example.com:8070/profile
curl -d '{"name":"vc-issuer-2", "uri":"http://vc-issuer-2.com", "signatureType":"Ed25519Signature2018", "did":"did:v1:test:nym:z6MkhLbRigh9utJNCaiEAdkqktz4r7yVBFDeaeqCeT7pRFnF","didPrivateKey":"5dF8yAW7hjLkJsfMXKqTPdDZUT56dX7Jq7TdXEtUEHHt2YUFAE34nQwyPCEp5XdWCKPSxs69xXqozsNh6MoJTmz5"}' -H "Content-Type: application/json" -X POST http://vcs.example.com:8070/profile
