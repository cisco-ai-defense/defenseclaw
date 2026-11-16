// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func secureClientCopilotTestConfig(connectors ...string) *config.Config {
	configured := map[string]config.PerConnectorGuardrailConfig{}
	for _, name := range connectors {
		configured[name] = config.PerConnectorGuardrailConfig{}
	}
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileSecureClient},
		Guardrail:      config.GuardrailConfig{Connectors: configured},
	}
}

// The Secure Client guardian publishes the GitHub Copilot drop-in, CLI-only,
// while Copilot is an enabled connector, and asks for its removal otherwise.
func TestEnterpriseHookSecureClientPlatformPrepareFollowsCopilot(t *testing.T) {
	previousCfg := cfg
	previousOptions, previousPublish := enterpriseHookSecureClientCopilotOptions, enterpriseHookSecureClientCopilotPublish
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookSecureClientCopilotOptions, enterpriseHookSecureClientCopilotPublish = previousOptions, previousPublish
	})
	enterpriseHookSecureClientCopilotOptions = func(hookBinary string) (enterprisepolicy.Options, error) {
		if hookBinary != "" {
			t.Fatalf("the guardian must publish for its own launcher, got %q", hookBinary)
		}
		return enterprisepolicy.Options{GOOS: "windows", CopilotCLIPolicyOnly: true}, nil
	}
	var calls []bool
	enterpriseHookSecureClientCopilotPublish = func(opts enterprisepolicy.Options, enabled bool) (enterprisepolicy.State, error) {
		if !opts.CopilotCLIPolicyOnly {
			t.Fatal("the Secure Client Copilot policy must be CLI-only")
		}
		calls = append(calls, enabled)
		return enterprisepolicy.State{}, nil
	}

	cfg = secureClientCopilotTestConfig("codex", "copilot")
	var log bytes.Buffer
	enterpriseHookStandalonePlatformPrepare(&log)
	cfg = secureClientCopilotTestConfig("codex")
	enterpriseHookStandalonePlatformPrepare(&log)
	if len(calls) != 2 || !calls[0] || calls[1] {
		t.Fatalf("publish calls = %v, want [true false]", calls)
	}
	if log.Len() != 0 {
		t.Fatalf("unexpected guardian output: %s", log.String())
	}

	enterpriseHookSecureClientCopilotPublish = func(enterprisepolicy.Options, bool) (enterprisepolicy.State, error) {
		return enterprisepolicy.State{}, errors.New("policy.d is not administrator-owned")
	}
	enterpriseHookStandalonePlatformPrepare(&log)
	if !strings.Contains(log.String(), "GitHub Copilot machine policy (Windows Secure Client): policy.d is not administrator-owned") {
		t.Fatalf("a publish failure was not reported: %s", log.String())
	}
}

// Managed-hook teardown takes Copilot rows on Secure Client and still refuses
// the per-user connectors that profile does not manage.
func TestWindowsManagedHooksTeardownTargetsSecureClientCopilot(t *testing.T) {
	if enterprisehooks.WindowsStandaloneProcess() {
		t.Skip("the test process carries the standalone profile pin")
	}
	row := func(connectorName string) enterprisehooks.Manifest {
		enabled := true
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
			SID:          "S-1-5-21-1-2-3-1001",
			UserHome:     `C:\Users\alice`,
			Connector:    connectorName,
			AgentVersion: "1.0.90",
			Enabled:      &enabled,
		}}}
	}
	targets, _, _, _, err := windowsManagedHooksTeardownTargets(row("copilot"))
	if err != nil || len(targets) != 1 || targets[0].Connector != "copilot" {
		t.Fatalf("Secure Client copilot teardown targets = %+v err=%v", targets, err)
	}
	if _, _, _, _, err := windowsManagedHooksTeardownTargets(row("devin")); err == nil ||
		!strings.Contains(err.Error(), `does not support connector "devin"`) {
		t.Fatalf("Secure Client devin teardown error = %v", err)
	}
}
