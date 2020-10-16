/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cucumber/godog"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/fabric-peer-test-common/bddtests"
)

const (
	networkName   = "test-network"
	sdkConfigPath = "./fixtures/fabric/config/sdk-client/config.yaml"
)

var logger = log.New("fabric-cli")

// FabricCLISteps extend the BDD test with Fabric CLI steps
type FabricCLISteps struct {
	BDDContext *bddtests.BDDContext
}

// NewFabricCLISteps returns fabric-cli BDD steps
func NewFabricCLISteps(context *bddtests.BDDContext) *FabricCLISteps {
	return &FabricCLISteps{BDDContext: context}
}

func (d *FabricCLISteps) installPlugin(path string) error {
	logger.Infof("Installing fabric-cli plugin from path [%s]", path)

	_, err := NewFabricCLI().Exec("plugin", "install", path)

	return err
}

func (d *FabricCLISteps) initNetwork() error {
	logger.Infof("Initializing fabric-cli network. Network name [%s], SDK Config Path [%s]",
		networkName, sdkConfigPath)

	err := os.RemoveAll(homeDir)
	if err != nil {
		return err
	}

	out, err := NewFabricCLI().Exec("network", "set", networkName, sdkConfigPath)
	if err != nil {
		logger.Errorf("Error: %s:%s", err, out)
	}

	return err
}

func (d *FabricCLISteps) defineContext(name, channelID, orgID, strPeers, userID string) error {
	logger.Infof("Defining fabric-cli context [%s] for channel [%s], org [%s], peers %s and User ID [%s]",
		name, channelID, orgID, strPeers, userID)

	peers := strings.Split(strPeers, ",")
	if len(peers) == 0 {
		return errors.New("at least one peer must be specified")
	}

	var args []string
	args = append(args, "context", "set", name, "--network", networkName, "--channel", channelID, "--user", userID, "--organization", orgID) //nolint: lll

	for _, peer := range peers {
		args = append(args, "--peers", peer)
	}

	_, err := NewFabricCLI().Exec(args...)

	return err
}

func (d *FabricCLISteps) useContext(name string) error {
	logger.Infof("Using fabric-cli context [%s]", name)

	_, err := NewFabricCLI().Exec("context", "use", name)

	return err
}

func (d *FabricCLISteps) execute(strArgs string) error {
	logger.Infof("Executing fabric-cli command with args [%s]", strArgs)

	bddtests.ClearResponse()

	args, err := bddtests.ResolveAllVars(strings.ReplaceAll(strArgs, " ", ","))
	if err != nil {
		return err
	}

	logger.Infof("Executing fabric-cli with args: %s ...", args)

	response, err := NewFabricCLI().Exec(args...)
	if err != nil {
		return err
	}

	logger.Infof("... got response: %s", response)

	bddtests.SetResponse(response)

	return nil
}

func (d *FabricCLISteps) setupScript(scriptPath string) error {
	logger.Infof("Executing setup script %s", scriptPath)

	_, err := execCMD(scriptPath)

	return err
}

func execCMD(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...) // nolint: gosec

	var out bytes.Buffer

	var er bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &er

	err := cmd.Start()
	if err != nil {
		return "", fmt.Errorf(er.String())
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf(er.String())
	}

	return out.String(), nil
}

// RegisterSteps registers transient data steps
func (d *FabricCLISteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(d.BDDContext.BeforeScenario)
	s.AfterScenario(d.BDDContext.AfterScenario)
	s.Step(`^fabric-cli network is initialized$`, d.initNetwork)
	s.Step(`^fabric-cli plugin "([^"]*)" is installed$`, d.installPlugin)
	s.Step(`^fabric-cli context "([^"]*)" is defined on channel "([^"]*)" with org "([^"]*)", peers "([^"]*)" and user "([^"]*)"$`, d.defineContext) //nolint: lll
	s.Step(`^fabric-cli context "([^"]*)" is used$`, d.useContext)
	s.Step(`^fabric-cli is executed with args "([^"]*)"$`, d.execute)
	s.Step(`^fabric-cli setup script "([^"]*)" is executed$`, d.setupScript)
}
