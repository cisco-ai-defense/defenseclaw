// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-3 GAP-0235: on a standalone managed deployment `enterprise hooks
// install` refuses a connector the installed config does not publish, and
// says which connectors are enabled and what to do; a published connector
// and other deployments are unchanged.
func TestEnterpriseHookInstallRefusesAConnectorTheConfigDoesNotPublish(t *testing.T) {
	standalone := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	standalone.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {Mode: "observe"},
		"claudecode": {Mode: "action"},
	}
	err := enterpriseHookInstallConnectorPublished(standalone, "hermes")
	if err == nil {
		t.Fatal("hermes install on a config that publishes codex and claudecode: want a refusal")
	}
	for _, want := range []string{`connector "hermes" is not enabled`, "enabled: claudecode, codex", "guardrail.connectors"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err, want)
		}
	}
	for _, name := range []string{"codex", "claude-code"} {
		if err := enterpriseHookInstallConnectorPublished(standalone, name); err != nil {
			t.Fatalf("%s is published: %v", name, err)
		}
	}

	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	secureClient.Enterprise.Profile = managed.ProfileSecureClient
	secureClient.Guardrail.Connectors = standalone.Guardrail.Connectors
	if err := enterpriseHookInstallConnectorPublished(secureClient, "hermes"); err != nil {
		t.Fatalf("Secure Client install is unchanged: %v", err)
	}
	if err := enterpriseHookInstallConnectorPublished(&config.Config{}, "hermes"); err != nil {
		t.Fatalf("per-user config is unchanged: %v", err)
	}
}
