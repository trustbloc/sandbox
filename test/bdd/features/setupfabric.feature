#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@setup_fabric
Feature:
  Scenario: setup fabric
    Given DCAS collection config "dcas-cfg" is defined for collection "dcas" as policy="OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')", requiredPeerCount=2, maxPeerCount=3, and timeToLive=
    Given off-ledger collection config "diddoc-cfg" is defined for collection "diddoc" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=
    Given off-ledger collection config "fileidx-cfg" is defined for collection "fileidxdoc" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=
    Given off-ledger collection config "meta-data-cfg" is defined for collection "meta_data" as policy="OR('IMPLICIT-ORG.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=

    Given the channel "mychannel" is created and all peers have joined

    And "system" chaincode "configscc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member','Org3MSP.member')" with collection policy ""
    And "system" chaincode "sidetreetxn_cc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member','Org3MSP.member')" with collection policy "dcas-cfg"
    And "system" chaincode "document" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')" with collection policy "diddoc-cfg,fileidx-cfg,meta-data-cfg"

    Given DCAS collection config "consortium-files-cfg" is defined for collection "consortium" as policy="OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')", requiredPeerCount=2, maxPeerCount=3, and timeToLive=
    And "system" chaincode "file" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "OR('Org1MSP.member','Org2MSP.member','Org3MSP.member')" with collection policy "consortium-files-cfg"

    And fabric-cli network is initialized
    And fabric-cli plugin "../../.build/ledgerconfig" is installed
    And fabric-cli plugin "../../.build/file" is installed
    And fabric-cli context "mychannel" is defined on channel "mychannel" with org "peerorg1", peers "peer0.org1.example.com,peer1.org1.example.com" and user "User1"

    And we wait 10 seconds

    # Configure the following Sidetree namespaces on channel 'mychannel'
    Then fabric-cli context "mychannel" is used
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-consortium-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org1-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org2-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org3-config.json --noprompt"

    # Wait for the Sidetree services to start up on mychannel
    And we wait 10 seconds


    # Create a file index document
    When fabric-cli is executed with args "file createidx --path /.well-known/did-trustbloc --url https://peer0-org1.trustbloc.local/file --recoverypwd pwd1 --nextpwd pwd1 --noprompt"
    And the JSON path "id" of the response is saved to variable "fileIdxID"

    # Update the file handler configuration for the '/content' path with the ID of the file index document
    Then fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org1MSP --peers peer0.org1.example.com;peer1.org1.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org2MSP --peers peer0.org2.example.com;peer1.org2.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"
    And fabric-cli is executed with args "ledgerconfig fileidxupdate --msp Org3MSP --peers peer0.org3.example.com;peer1.org3.example.com --path /.well-known/did-trustbloc --idxid ${fileIdxID} --noprompt"

    Then we wait 10 seconds

    When an HTTP request is sent to "https://peer0-org1.trustbloc.local/file/${fileIdxID}"
    Then the JSON path "id" of the response equals "${fileIdxID}"

  # Upload a couple of files and add them to the file index document
    When fabric-cli is executed with args "file upload --url https://peer0-org1.trustbloc.local/.well-known/did-trustbloc --files ./fixtures/discovery-config/sidetree-fabric/config/consortium.json;./fixtures/discovery-config/sidetree-fabric/config/peer0-org1.trustbloc.local.json;./fixtures/discovery-config/sidetree-fabric/config/peer0-org2.trustbloc.local.json;fixtures/discovery-config/sidetree-fabric/config/peer0-org3.trustbloc.local.json --idxurl https://peer0-org1.trustbloc.local/file/${fileIdxID} --pwd pwd1 --nextpwd pwd2 --noprompt"
    Then the JSON path "#" of the response has 4 items
    And the JSON path "0.Name" of the response equals "consortium.json"
    And the JSON path "0.ContentType" of the response equals "application/json"
    And the JSON path "1.Name" of the response equals "peer0-org1.trustbloc.local.json"
    And the JSON path "1.ContentType" of the response equals "application/json"
    And the JSON path "2.Name" of the response equals "peer0-org2.trustbloc.local.json"
    And the JSON path "2.ContentType" of the response equals "application/json"
    And the JSON path "3.Name" of the response equals "peer0-org3.trustbloc.local.json"
    And the JSON path "3.ContentType" of the response equals "application/json"

    Then we wait 10 seconds

    # Resolve .well-known files
    When an HTTP request is sent to "https://peer1-org2.trustbloc.local/.well-known/did-trustbloc/consortium.json"
    Then response from "https://peer1-org2.trustbloc.local/.well-known/did-trustbloc/consortium.json" to client contains value "payload"
    When an HTTP request is sent to "https://peer0-org3.trustbloc.local/.well-known/did-trustbloc/peer0-org1.trustbloc.local.json"
    Then response from "https://peer0-org3.trustbloc.local/.well-known/did-trustbloc/peer0-org1.trustbloc.local.json" to client contains value "payload"
    When an HTTP request is sent to "https://peer0-org1.trustbloc.local/.well-known/did-trustbloc/peer0-org2.trustbloc.local.json"
    Then response from "https://peer0-org1.trustbloc.local/.well-known/did-trustbloc/peer0-org2.trustbloc.local.json" to client contains value "payload"
    When an HTTP request is sent to "https://peer1-org1.trustbloc.local/.well-known/did-trustbloc/peer0-org3.trustbloc.local.json"
    Then response from "https://peer1-org1.trustbloc.local/.well-known/did-trustbloc/peer0-org3.trustbloc.local.json" to client contains value "payload"
