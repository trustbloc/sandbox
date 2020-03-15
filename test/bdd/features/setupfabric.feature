#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@setup_fabric
Feature:
  Scenario: setup fabric
    Given DCAS collection config "dcas-mychannel" is defined for collection "dcas" as policy="OR('Org1MSP.member','Org2MSP.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=60m
    Given DCAS collection config "docs-mychannel" is defined for collection "docs" as policy="OR('Org1MSP.member','Org2MSP.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=60m
    Given off-ledger collection config "meta_data_coll" is defined for collection "meta_data" as policy="OR('Org1MSP.member','Org2MSP.member')", requiredPeerCount=0, maxPeerCount=0, and timeToLive=60m

    Given the channel "mychannel" is created and all peers have joined

    And "system" chaincode "configscc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member')" with collection policy ""
    And "system" chaincode "sidetreetxn_cc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "AND('Org1MSP.member','Org2MSP.member')" with collection policy "dcas-mychannel"
    And "system" chaincode "document_cc" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "OR('Org1MSP.member','Org2MSP.member')" with collection policy "docs-mychannel,meta_data_coll"

    Given DCAS collection config "consortium-files-coll" is defined for collection "consortium" as policy="OR('Org1MSP.member','Org2MSP.member')", requiredPeerCount=1, maxPeerCount=2, and timeToLive=60m
    And "system" chaincode "files" is instantiated from path "in-process" on the "mychannel" channel with args "" with endorsement policy "OR('Org1MSP.member','Org2MSP.member')" with collection policy "consortium-files-coll"

    And fabric-cli network is initialized
    And fabric-cli plugin "../../.build/ledgerconfig" is installed
    And fabric-cli context "mychannel" is defined on channel "mychannel" with org "peerorg1", peers "peer0.org1.example.com,peer1.org1.example.com" and user "User1"

    And we wait 10 seconds

    # Configure the following Sidetree namespaces on channel 'mychannel'
    Then fabric-cli context "mychannel" is used
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-consortium-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org1-config.json --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --configfile ./fixtures/fabric/config/ledger/mychannel-org2-config.json --noprompt"

    # Wait for the Sidetree services to start up on mychannel
    And we wait 10 seconds

    # Upload .well-known files
    When client sends request to "http://localhost:80/.well-known/did-trustbloc" to upload file "fixtures/discovery-config/sidetree-fabric/config/consortium.json" with content type "application/json"
    Then the ID of the file is saved to variable "wellKnownTrustblocID"
    When client sends request to "http://localhost:80/.well-known/did-trustbloc" to upload file "fixtures/discovery-config/sidetree-fabric/config/peer0.org1.example.com.json" with content type "application/json"
    Then the ID of the file is saved to variable "wellKnownOrg1ID"
    # Create the .well-known file index Sidetree document
    Given variable "wellKnownIndexFile" is assigned the JSON value '{"consortium.json":"${wellKnownTrustblocID}","peer0.org1.example.com.json":"${wellKnownOrg1ID}"}'
    When client sends request to "http://localhost:48526/file" to create document with content "${wellKnownIndexFile}" in namespace "file:idx"
    Then the ID of the returned document is saved to variable "wellKnownIndexID"

    # Update the ledger config to point to the index file documents
    Given variable "fileHandlerConfig" is assigned the JSON value '{"Handlers":[{"Description":"Consortium .wellknown files","BasePath":"/.well-known/did-trustbloc","ChaincodeName":"files","Collection":"consortium","IndexNamespace":"file:idx","IndexDocID":"${wellKnownIndexID}"}]}'
    And variable "org1ConfigUpdate" is assigned the JSON value '{"MspID":"Org1MSP","Peers":[{"PeerID":"peer0.org1.example.com","Apps":[{"AppName":"file-handler","Version":"1","Config":"${fileHandlerConfig}","Format":"json"}]},{"PeerID":"peer1.org1.example.com","Apps":[{"AppName":"file-handler","Version":"1","Config":"${fileHandlerConfig}","Format":"json"}]}]}'
    And variable "org2ConfigUpdate" is assigned the JSON value '{"MspID":"Org2MSP","Peers":[{"PeerID":"peer0.org2.example.com","Apps":[{"AppName":"file-handler","Version":"1","Config":"${fileHandlerConfig}","Format":"json"}]},{"PeerID":"peer1.org2.example.com","Apps":[{"AppName":"file-handler","Version":"1","Config":"${fileHandlerConfig}","Format":"json"}]}]}'
    And fabric-cli is executed with args "ledgerconfig update --config ${org1ConfigUpdate} --noprompt"
    And fabric-cli is executed with args "ledgerconfig update --config ${org2ConfigUpdate} --noprompt"

    # Resolve .well-known files
    When client sends request to "http://localhost:48626/.well-known/did-trustbloc/consortium.json" to retrieve file
    Then the retrieved file contains "payload"
    When client sends request to "http://localhost:48626/.well-known/did-trustbloc/peer0.org1.example.com.json" to retrieve file
    Then the retrieved file contains "payload"
