// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func legacyStandaloneConfig() *config.Config {
	cfg := &config.Config{}
	cfg.OpenShell.Mode = "standalone"
	cfg.Guardrail.Host = "10.200.0.1"
	cfg.Gateway.APIPort = 18970
	return cfg
}

// Every API listener, hook/plugin address, and health probe must agree on one
// address, or an upgrade health check on a legacy host dials 127.0.0.1 while
// the API listens on the veth host (or the reverse) and rolls back.
func TestAPIListenAddrUsesTheLegacyBindShim(t *testing.T) {
	legacy := legacyStandaloneConfig()
	if got := apiListenAddr(legacy); got != "10.200.0.1:18970" {
		t.Fatalf("legacy listener = %q, want the veth host", got)
	}
	legacy.Gateway.APIBind = "127.0.0.1"
	if got := apiListenAddr(legacy); got != "127.0.0.1:18970" {
		t.Fatalf("explicit api_bind listener = %q", got)
	}
	host := &config.Config{}
	host.Guardrail.Host = "10.200.0.1"
	host.Gateway.APIPort = 18970
	if got := apiListenAddr(host); got != "127.0.0.1:18970" {
		t.Fatalf("host-mode listener = %q, want loopback", got)
	}
}

func TestAPINeedsRestartOnlyWhenTheShimStateChanges(t *testing.T) {
	legacy := legacyStandaloneConfig()
	cleaned := legacyStandaloneConfig()
	cleaned.OpenShell.Mode = ""
	if !apiNeedsRestart(legacy, cleaned) {
		t.Fatal("leaving legacy standalone mode must move the API listener")
	}
	moved := legacyStandaloneConfig()
	moved.OpenShell.SandboxHome = "/srv/sandbox"
	if apiNeedsRestart(legacy, moved) {
		t.Fatal("a legacy-only openshell sub-key must not bounce the API listener")
	}
}

func TestDiffConfigsTreatsLegacyOpenShellKeysAsHotExceptTheModeFlip(t *testing.T) {
	oldCfg := legacyStandaloneConfig()
	newCfg := legacyStandaloneConfig()
	newCfg.OpenShell.SandboxHome = "/srv/sandbox"
	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "openshell") || len(diff.RestartRequired) != 0 {
		t.Fatalf("sandbox_home change: changed=%v restart=%v, want hot", diff.Changed, diff.RestartRequired)
	}

	newCfg = legacyStandaloneConfig()
	newCfg.OpenShell.Mode = ""
	diff = diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.RestartRequired, "openshell.mode") {
		t.Fatalf("restart_required = %v, want openshell.mode", diff.RestartRequired)
	}
}

func TestLegacySandboxHealthIsDegradedWithCleanupRemediation(t *testing.T) {
	s := &Sidecar{cfg: legacyStandaloneConfig(), health: NewSidecarHealth()}
	s.reportLegacySandboxHealth()
	sandbox := s.health.Snapshot().Sandbox
	if sandbox == nil {
		t.Fatal("legacy install must report the sandbox subsystem")
	}
	if sandbox.State != StateDegraded {
		t.Fatalf("sandbox state = %q, want %q", sandbox.State, StateDegraded)
	}
	if sandbox.LastError != legacySandboxHealthError {
		t.Fatalf("sandbox last_error = %q", sandbox.LastError)
	}
	if sandbox.Details["api_bind"] != "10.200.0.1" || sandbox.Details["remediation"] != "defenseclaw sandbox legacy-cleanup" {
		t.Fatalf("sandbox details = %#v", sandbox.Details)
	}

	host := &Sidecar{cfg: &config.Config{}, health: NewSidecarHealth()}
	host.reportLegacySandboxHealth()
	if got := host.health.Snapshot().Sandbox; got != nil {
		t.Fatalf("host-mode install reported a sandbox subsystem: %#v", got)
	}
}
