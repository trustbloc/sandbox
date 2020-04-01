/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/spf13/viper"
	"github.com/trustbloc/fabric-peer-test-common/bddtests"
)

func TestMain(m *testing.M) {
	projectPath, err := filepath.Abs("../..")
	if err != nil {
		panic(err.Error())
	}

	if err := os.Setenv("PROJECT_PATH", projectPath); err != nil {
		panic(err.Error())
	}

	tags := "setup_fabric"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	initBDDConfig()

	status := godog.RunWithOptions("godogs", func(s *godog.Suite) {
		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})

	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func FeatureContext(s *godog.Suite) {
	peersMspID := make(map[string]string)
	peersMspID["peer0.org1.example.com"] = "Org1MSP"
	peersMspID["peer1.org1.example.com"] = "Org1MSP"
	peersMspID["peer0.org2.example.com"] = "Org2MSP"
	peersMspID["peer1.org2.example.com"] = "Org2MSP"
	peersMspID["peer0.org3.example.com"] = "Org3MSP"
	peersMspID["peer1.org3.example.com"] = "Org3MSP"

	fabricTestCtx, err := bddtests.NewBDDContext([]string{"peerorg1", "peerorg2", "peerorg3"},
		"orderer.example.com", "./fixtures/fabric/config/sdk-client/",
		"config.yaml", peersMspID, "", "")
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}
	// Context is shared between tests
	bddtests.NewCommonSteps(fabricTestCtx).RegisterSteps(s)
	NewOffLedgerSteps(fabricTestCtx).RegisterSteps(s)
	NewFabricCLISteps(fabricTestCtx).RegisterSteps(s)
}

func initBDDConfig() {
	replacer := strings.NewReplacer(".", "_")

	viper.AddConfigPath("./fixtures/fabric/config/sdk-client/")
	viper.SetConfigName("config")
	viper.SetEnvPrefix("core")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(replacer)

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Fatal error reading config file: %s \n", err)
		os.Exit(1)
	}
}
