/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"crypto/tls"
	"flag"
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/common"
	"github.com/trustbloc/sandbox/test/bdd/ace/pkg/gatekeeper"
)

const (
	caCertPath = "../../../k8s/.core/orb/kustomize/orb/overlays/local/certs/ca.crt"
)

var (
	logger    = log.New("ace-bdd")
	tlsConfig *tls.Config //nolint:gochecknoglobals
)

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all but excluding those marked with @wip
	tags := "@all && ~@wip"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func runBDDTests(tags, format string) int {
	return godog.TestSuite{
		Name:                 "ACE test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	if os.Getenv("DISABLE_CUSTOM_CA") != "true" {
		rootCAs, err := tlsutil.GetCertPool(false, []string{caCertPath})
		if err != nil {
			logger.Fatalf("Failed to create root CA: %s", err.Error())

			return
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		}
	}
}

type feature interface {
	// RegisterSteps registers scenario steps.
	RegisterSteps(sc *godog.ScenarioContext)
}

func initializeScenario(sc *godog.ScenarioContext) {
	commonSteps, err := common.NewSteps(tlsConfig)
	if err != nil {
		panic(err)
	}

	commonSteps.RegisterSteps(sc)

	features := []feature{
		gatekeeper.NewSteps(commonSteps),
	}

	for _, f := range features {
		f.RegisterSteps(sc)
	}
}

func buildOptions(tags, format string) *godog.Options {
	return &godog.Options{
		Tags:          tags,
		Format:        format,
		Strict:        true,
		StopOnFailure: true,
	}
}
