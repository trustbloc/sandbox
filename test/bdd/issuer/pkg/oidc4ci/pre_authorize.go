/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"
	"os"

	"github.com/cucumber/godog"
	"github.com/trustbloc/vcs/component/wallet-cli/cmd"
)

type PreAuthorizeStep struct {
	format         string
	credentialType string
	finalResult    error
}

func (s *PreAuthorizeStep) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^User wants to receive credentials with format "([^"]*)" and type "([^"]*)"$`, s.setCredentialType)
	sc.Step(`^User request issuer to start pre-authorization flow$`, s.executeCmd)
	sc.Step(`^no error is occurred$`, s.validateNoError)
}

func (s *PreAuthorizeStep) setCredentialType(_ context.Context, format string, credentialType string) {
	s.format = format
	s.credentialType = credentialType
}

func (s *PreAuthorizeStep) executeCmd(_ context.Context) error {
	preAuthorizeUrl := os.Getenv("ISSUER_PRE_AUTHORIZE_URL")
	if preAuthorizeUrl == "" {
		return fmt.Errorf("env: ISSUER_PRE_AUTHORIZE_URL should not be empty")
	}

	contextProviderUrl := os.Getenv("CONTEXT_PROVIDER_URL")
	if contextProviderUrl == "" {
		return fmt.Errorf("env: CONTEXT_PROVIDER_URL should not be empty")
	}

	didDomain := os.Getenv("DID_DOMAIN")
	if didDomain == "" {
		return fmt.Errorf("env: DID_DOMAIN should not be empty")
	}

	didServiceAuthToken := os.Getenv("DID_SERVICE_AUTH_TOKEN")
	uniResolverUrl := os.Getenv("UNI_RESOLVER_URL")
	if uniResolverUrl == "" {
		return fmt.Errorf("env: UNI_RESOLVER_URL should not be empty")
	}

	insecureTLS := os.Getenv("INSECURE_TLS")
	vcFormat := os.Getenv("VC_FORMAT")
	vcType := os.Getenv("VC_TYPE")
	didMethod := os.Getenv("DID_METHOD")
	didKeyType := os.Getenv("DID_KEY_TYPE")

	oidc4CICmd := cmd.NewOIDC4CICommand()
	oidc4CICmd.SetArgs([]string{
		"--grant-type", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		"--demo-issuer-url", preAuthorizeUrl,
		"--credential-format", s.format,
		"--credential-type", s.credentialType,
		"--context-provider-url", contextProviderUrl,
		"--did-domain", didDomain,
		"--did-method", didMethod,
		"--did-key-type", didKeyType,
		"--did-service-auth-token", didServiceAuthToken,
		"--uni-resolver-url", uniResolverUrl,
		"--insecure", insecureTLS,
		"--credential-type", vcType,
		"--credential-format", vcFormat,
	})
	s.finalResult = oidc4CICmd.Execute()

	return nil
}

func (s *PreAuthorizeStep) validateNoError(_ context.Context) error {
	return s.finalResult
}
