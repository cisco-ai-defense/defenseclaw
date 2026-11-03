// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"
)

// TestConnectorDisabledIsTheExplicitEnabledFalse pins the predicate the hook
// gates and the managed hook socket share (rel-1-0-6:GAP-0325): only an
// explicit enabled: false of a connector the manual control plane names
// disables it; aliases fold to the canonical name.
func TestConnectorDisabledIsTheExplicitEnabledFalse(t *testing.T) {
	off, on := false, true
	cfg := &Config{Guardrail: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
		"Codex":       {Enabled: &off},
		"claude-code": {Enabled: &on},
		"opencode":    {},
		"cursor":      {Enabled: &off},
	}}}
	for name, want := range map[string]bool{"codex": true, "cursor": true, "claudecode": false, "opencode": false, "hermes": false, "": false} {
		if got := cfg.ConnectorDisabled(name); got != want {
			t.Errorf("ConnectorDisabled(%q) = %v, want %v", name, got, want)
		}
	}
	if got := cfg.Guardrail.DisabledConnectors(); !reflect.DeepEqual(got, []string{"codex", "cursor"}) {
		t.Fatalf("DisabledConnectors = %v", got)
	}
	var none *Config
	if none.ConnectorDisabled("codex") || (*GuardrailConfig)(nil).DisabledConnectors() != nil {
		t.Fatal("a nil config disables nothing")
	}
}
