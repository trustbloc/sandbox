#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

curl -d '{"name":"demo", "did":"did:demo:abc", "uri":"http://demo.com", "signatureType":"Ed25519Signature2018", "creator":"did:demo:abc#key1" }' -H "Content-Type: application/json" -X POST http://localhost:8070/profile
