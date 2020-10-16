#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@setup_fabric
Feature:
  Scenario: setup fabric
    Given the channel "mychannel" is created and all peers have joined

    Then we wait 10 seconds

    Given DCAS collection config "dcas-cfg" is defined for collection "dcas" as policy="OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=
    Given off-ledger collection config "fileidx-cfg" is defined for collection "fileidxdoc" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=0, maxPeerCount=0, and timeToLive=
    Given off-ledger collection config "meta-data-cfg" is defined for collection "meta_data" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=0, maxPeerCount=0, and timeToLive=
    Given DCAS collection config "consortium-files-cfg" is defined for collection "consortium" as policy="OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=
    Given off-ledger collection config "diddoc-cfg" is defined for collection "diddoc" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=0, maxPeerCount=0, and timeToLive=

    Then chaincode "configscc", version "v1", package ID "configscc:v1", sequence 1 is approved and committed by orgs "peerorg1,peerorg2,peerorg3" on the "mychannel" channel with endorsement policy "AND('Org1MSP.member','Org2MSP.member','Org3MSP.member')" and collection policy ""
    And chaincode "sidetreetxn", version "v1", package ID "sidetreetxn:v1", sequence 1 is approved and committed by orgs "peerorg1,peerorg2,peerorg3" on the "mychannel" channel with endorsement policy "AND('Org1MSP.member','Org2MSP.member','Org3MSP.member')" and collection policy "dcas-cfg"
    And chaincode "document", version "v1", package ID "document:v1", sequence 1 is approved and committed by orgs "peerorg1,peerorg2,peerorg3" on the "mychannel" channel with endorsement policy "OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')" and collection policy "diddoc-cfg,fileidx-cfg,meta-data-cfg"
    And chaincode "file", version "v1", package ID "file:v1", sequence 1 is approved and committed by orgs "peerorg1,peerorg2,peerorg3" on the "mychannel" channel with endorsement policy "OR('Org1MSP.member','Org2MSP.member','Org3MSP.member' )" and collection policy "consortium-files-cfg"

    Then we wait 10 seconds

    And fabric-cli network is initialized
    And fabric-cli plugin "../../.build/ledgerconfig" is installed
    And fabric-cli plugin "../../.build/file" is installed
    And fabric-cli context "org1-context" is defined on channel "mychannel" with org "peerorg1", peers "peer0.org1.example.com,peer1.org1.example.com" and user "User1"
    And fabric-cli context "org2-context" is defined on channel "mychannel" with org "peerorg2", peers "peer0.org2.example.com,peer1.org2.example.com" and user "User1"
    And fabric-cli context "org3-context" is defined on channel "mychannel" with org "peerorg3", peers "peer0.org3.example.com,peer1.org3.example.com" and user "User1"

    # Configure the following Sidetree namespaces on channel 'mychannel'
    Then fabric-cli context "org1-context" is used
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-consortium-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org1-config.json --noprompt"
    Then fabric-cli context "org2-context" is used
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org2-config.json --noprompt"
    Then fabric-cli context "org3-context" is used
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org3-config.json --noprompt"

    # Wait for the Sidetree services to start up on mychannel
    And we wait 10 seconds

    # Check blockchain endpoint
    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/sidetree/0.0.1/blockchain/version"
    Then the JSON path "name" of the response equals "Hyperledger Fabric"
    And the JSON path "version" of the response equals "2.2.0"

    # Check cas endpoint
    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/sidetree/0.0.1/cas/version"
    Then the JSON path "name" of the response equals "cas"
    And the JSON path "version" of the response equals "0.1.3"

    Given variable "token_fileidx_w" is assigned the value "TOKEN_FILEIDX_W"

    # generate trustbloc config file
    Then fabric-cli setup script "./fixtures/discovery-config/sidetree-fabric/generate_did_method_config_fabric.sh" is executed

    # Create a file index document
    Then fabric-cli context "org1-context" is used
    When fabric-cli is executed with args "file createidx --path /.well-known/did-trustbloc --url https://peer0-org1.trustbloc.local/file --recoverykeyfile ./fixtures/keys/recover/public.pem --updatekeyfile ./fixtures/keys/update/public.pem --authtoken ${token_fileidx_w} --noprompt"
    And the JSON path "id" of the response is saved to variable "fileIdxID"

    When fabric-cli is executed with args "file createidx --path /.well-known --url https://peer0-org1.trustbloc.local/file --recoverykeyfile ./fixtures/keys/recover-org1/public.pem --updatekeyfile ./fixtures/keys/update-org1/public.pem --authtoken ${token_fileidx_w} --noprompt"
    And the JSON path "id" of the response is saved to variable "org1FileIdxID"

    Then fabric-cli context "org2-context" is used
    When fabric-cli is executed with args "file createidx --path /.well-known --url https://peer0-org2.trustbloc.local/file --recoverykeyfile ./fixtures/keys/recover-org2/public.pem --updatekeyfile ./fixtures/keys/update-org2/public.pem --authtoken ${token_fileidx_w} --noprompt"
    And the JSON path "id" of the response is saved to variable "org2FileIdxID"

    Then fabric-cli context "org3-context" is used
    When fabric-cli is executed with args "file createidx --path /.well-known --url https://peer0-org3.trustbloc.local/file --recoverykeyfile ./fixtures/keys/recover-org3/public.pem --updatekeyfile ./fixtures/keys/update-org3/public.pem --authtoken ${token_fileidx_w} --noprompt"
    And the JSON path "id" of the response is saved to variable "org3FileIdxID"

    Then we wait 10 seconds

    # Update the file handler configuration for the '/content' path with the ID of the file index document
    Then fabric-cli context "org1-context" is used
    Then fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org1MSP --peers peer0.org1.example.com;peer1.org1.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"
    Then fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org1MSP --peers peer0.org1.example.com;peer1.org1.example.com --path /.well-known --idxid ${org1FileIdxID} --noprompt"
    Then fabric-cli context "org2-context" is used
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org2MSP --peers peer0.org2.example.com;peer1.org2.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org2MSP --peers peer0.org2.example.com;peer1.org2.example.com --path /.well-known --idxid ${org2FileIdxID} --noprompt"
    Then fabric-cli context "org3-context" is used
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org3MSP --peers peer0.org3.example.com;peer1.org3.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org3MSP --peers peer0.org3.example.com;peer1.org3.example.com --path /.well-known --idxid ${org3FileIdxID} --noprompt"

    Then we wait 10 seconds

    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/file/${fileIdxID}"
    Then the JSON path "didDocument.id" of the response equals "${fileIdxID}"

    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/file/${org1FileIdxID}"
    Then the JSON path "didDocument.id" of the response equals "${org1FileIdxID}"

    When an HTTP GET is sent to "https://peer0-org2.trustbloc.local/file/${org2FileIdxID}"
    Then the JSON path "didDocument.id" of the response equals "${org2FileIdxID}"

    When an HTTP GET is sent to "https://peer0-org3.trustbloc.local/file/${org3FileIdxID}"
    Then the JSON path "didDocument.id" of the response equals "${org3FileIdxID}"

  # Upload a couple of files and add them to the file index document
    When fabric-cli is executed with args "file upload --url https://peer0-org1.trustbloc.local/.well-known/did-trustbloc --files ./fixtures/discovery-config/sidetree-fabric/config/did-trustbloc/testnet.trustbloc.local.json;./fixtures/discovery-config/sidetree-fabric/config/did-trustbloc/org1.trustbloc.local.json;./fixtures/discovery-config/sidetree-fabric/config/did-trustbloc/org2.trustbloc.local.json;fixtures/discovery-config/sidetree-fabric/config/did-trustbloc/org3.trustbloc.local.json --idxurl https://peer0-org1.trustbloc.local/file/${fileIdxID} --signingkeyfile ./fixtures/keys/update/key.pem --nextupdatekeyfile ./fixtures/keys/update2/public.pem --authtoken ${token_fileidx_w} --noprompt"
    Then the JSON path "#" of the response has 4 items
    And the JSON path "0.Name" of the response equals "testnet.trustbloc.local.json"
    And the JSON path "0.ContentType" of the response equals "application/json"
    And the JSON path "1.Name" of the response equals "org1.trustbloc.local.json"
    And the JSON path "1.ContentType" of the response equals "application/json"
    And the JSON path "2.Name" of the response equals "org2.trustbloc.local.json"
    And the JSON path "2.ContentType" of the response equals "application/json"
    And the JSON path "3.Name" of the response equals "org3.trustbloc.local.json"
    And the JSON path "3.ContentType" of the response equals "application/json"

    When fabric-cli is executed with args "file upload --url https://peer0-org1.trustbloc.local/.well-known --files ./fixtures/discovery-config/sidetree-fabric/config/org1.trustbloc.local/did-configuration.json --idxurl https://peer0-org1.trustbloc.local/file/${org1FileIdxID} --signingkeyfile ./fixtures/keys/update-org1/key.pem --nextupdatekeyfile ./fixtures/keys/update2-org1/public.pem --authtoken ${token_fileidx_w} --noprompt"
    Then the JSON path "#" of the response has 1 items
    And the JSON path "0.Name" of the response equals "did-configuration.json"
    And the JSON path "0.ContentType" of the response equals "application/json"

    When fabric-cli is executed with args "file upload --url https://peer0-org2.trustbloc.local/.well-known --files ./fixtures/discovery-config/sidetree-fabric/config/org2.trustbloc.local/did-configuration.json --idxurl https://peer0-org2.trustbloc.local/file/${org2FileIdxID} --signingkeyfile ./fixtures/keys/update-org2/key.pem --nextupdatekeyfile ./fixtures/keys/update2-org2/public.pem --authtoken ${token_fileidx_w} --noprompt"
    Then the JSON path "#" of the response has 1 items
    And the JSON path "0.Name" of the response equals "did-configuration.json"
    And the JSON path "0.ContentType" of the response equals "application/json"

    When fabric-cli is executed with args "file upload --url https://peer0-org3.trustbloc.local/.well-known --files ./fixtures/discovery-config/sidetree-fabric/config/org3.trustbloc.local/did-configuration.json --idxurl https://peer0-org3.trustbloc.local/file/${org3FileIdxID} --signingkeyfile ./fixtures/keys/update-org3/key.pem --nextupdatekeyfile ./fixtures/keys/update2-org3/public.pem --authtoken ${token_fileidx_w} --noprompt"
    Then the JSON path "#" of the response has 1 items
    And the JSON path "0.Name" of the response equals "did-configuration.json"
    And the JSON path "0.ContentType" of the response equals "application/json"

    Then we wait 15 seconds

    # Resolve .well-known files
    When an HTTP GET is sent to "https://peer1-org2.trustbloc.local/.well-known/did-trustbloc/testnet.trustbloc.local.json"
    Then response from "https://peer1-org2.trustbloc.local/.well-known/did-trustbloc/testnet.trustbloc.local.json" to client contains value "payload"
    When an HTTP GET is sent to "https://peer0-org3.trustbloc.local/.well-known/did-trustbloc/org1.trustbloc.local.json"
    Then response from "https://peer0-org3.trustbloc.local/.well-known/did-trustbloc/org1.trustbloc.local.json" to client contains value "payload"
    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/.well-known/did-trustbloc/org2.trustbloc.local.json"
    Then response from "https://peer0-org1.trustbloc.local/.well-known/did-trustbloc/org2.trustbloc.local.json" to client contains value "payload"
    When an HTTP GET is sent to "https://peer1-org1.trustbloc.local/.well-known/did-trustbloc/org3.trustbloc.local.json"
    Then response from "https://peer1-org1.trustbloc.local/.well-known/did-trustbloc/org3.trustbloc.local.json" to client contains value "payload"

    # Resolve did-configuration
    When an HTTP GET is sent to "https://peer0-org1.trustbloc.local/.well-known/did-configuration.json"
    Then response from "https://peer0-org1.trustbloc.local/.well-known/did-configuration.json" to client contains value "entries"
    When an HTTP GET is sent to "https://peer0-org2.trustbloc.local/.well-known/did-configuration.json"
    Then response from "https://peer0-org2.trustbloc.local/.well-known/did-configuration.json" to client contains value "entries"
    When an HTTP GET is sent to "https://peer0-org3.trustbloc.local/.well-known/did-configuration.json"
    Then response from "https://peer0-org3.trustbloc.local/.well-known/did-configuration.json" to client contains value "entries"
