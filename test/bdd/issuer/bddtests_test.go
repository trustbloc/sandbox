/*
Copyright Avast Software. All Rights Reserved.

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

	"github.com/trustbloc/sandbox/test/bdd/issuer/pkg/oidc4ci"
)

const (
	caCertPath = "../../../k8s/.core/orb/kustomize/orb/overlays/local/certs/ca.crt"
)

var (
	logger    = log.New("issuer-bdd")
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
		Name:                "Issuer test suite",
		ScenarioInitializer: initializeScenario,
		Options:             buildOptions(tags, format),
	}.Run()
}

type feature interface {
	// RegisterSteps registers scenario steps.
	RegisterSteps(sc *godog.ScenarioContext)
}

func initializeScenario(sc *godog.ScenarioContext) {
	features := []feature{
		&oidc4ci.PreAuthorizeStep{},
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
