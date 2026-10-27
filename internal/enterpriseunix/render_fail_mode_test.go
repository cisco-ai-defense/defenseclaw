// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The runtime descriptor names each connector the administrator's config
// resolves open (owner decision 2026-10-20), so the `--enterprise-managed`
// hook runtime can honor it; none when nothing is open.
func TestOpenHookConnectorsFollowTheAdministratorsConfig(t *testing.T) {
	loaded := &config.Config{DeploymentMode: "managed_enterprise"}
	loaded.Enterprise.Profile = "standalone"
	loaded.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {HookFailMode: "open"},
		"kiro":  {HookFailMode: "closed"},
	}
	cfg := &validatedConfig{Connectors: []string{"kiro", "codex"}, Loaded: loaded}
	if got := strings.Join(openHookConnectors(cfg, []string{"codex", "claudecode"}), ","); got != "codex" {
		t.Fatalf("open hook connectors = %q, want codex", got)
	}
	loaded.Guardrail.HookFailMode = "open"
	if got := strings.Join(openHookConnectors(cfg, []string{"claudecode"}), ","); got != "claudecode,codex" {
		t.Fatalf("global open: open hook connectors = %q, want claudecode,codex", got)
	}
	loaded.Guardrail.HookFailMode = ""
	loaded.Guardrail.Connectors = nil
	if got := openHookConnectors(cfg, []string{"codex"}); got != nil {
		t.Fatalf("unset fail mode: open hook connectors = %q, want none", got)
	}
	if got := openHookConnectors(nil, nil); got != nil {
		t.Fatalf("no config: %q", got)
	}
}

// GAP-0362 (LEAD DECISION): an administrator's explicit per-connector open
// for a connector outside the enrolled list (Hermes registered per user on a
// managed host) reaches the descriptor, so the native managed hook honours
// it during an outage; a closed peer stays closed.
func TestOpenHookConnectorsKeepAnExplicitOpenOutsideTheEnrolledList(t *testing.T) {
	loaded := &config.Config{DeploymentMode: "managed_enterprise"}
	loaded.Enterprise.Profile = "standalone"
	loaded.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {HookFailMode: "open"},
		"claudecode": {HookFailMode: "closed"},
		"hermes":     {HookFailMode: "open"},
		"kiro":       {HookFailMode: "closed"},
	}
	cfg := &validatedConfig{Connectors: []string{"codex", "claudecode"}, Loaded: loaded}
	if got := strings.Join(openHookConnectors(cfg, []string{"codex", "claudecode"}), ","); got != "codex,hermes" {
		t.Fatalf("open hook connectors = %q, want codex,hermes", got)
	}
}
