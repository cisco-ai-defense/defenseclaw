// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedHookFailMode is the value the renderer writes: a connector whose
// agent cannot fail closed (Hermes, Copilot) gets an open hook even when the
// config resolves closed, so status must not say closed (GAP-0001).
func TestManagedHookFailModeIsTheRenderedValue(t *testing.T) {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"hermes": closed, "copilot": closed, "opencode": closed, "amp": {HookFailMode: "open"},
	}
	for _, name := range []string{"hermes", "copilot"} {
		if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
			t.Fatalf("%s: the config resolves %q; the test needs closed", name, got)
		}
	}
	want := map[string]string{
		"hermes": "open", "copilot": "open", // cannot fail closed
		"codex": "closed", "claudecode": "closed", "opencode": "closed",
		"amp": "open", // configured open stays open
	}
	if runtime.GOOS == "windows" {
		// The Windows renderer pins every standalone per-user connector closed
		// whatever the config says (windowsEnterpriseHookFailMode).
		want["amp"] = "closed"
	}
	for name, mode := range want {
		if got := ManagedHookFailMode(cfg, name); got != mode {
			t.Errorf("%s: ManagedHookFailMode = %q, the renderer writes %q", name, got, mode)
		}
	}
	if got := renderedHookFailModeFor("not-a-connector", "closed"); got != "closed" {
		t.Errorf("unknown connector = %q", got)
	}
}
