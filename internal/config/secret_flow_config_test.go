// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretFlowDefaults proves the shipped defaults: shadow lane, credentials
// on, default alert / strict block (a managed install follows its pack),
// re-encodings on, caps set.
func TestSecretFlowDefaults(t *testing.T) {
	cfg := DefaultConfig()
	sf := cfg.Guardrail.SecretFlow
	if got := cfg.Guardrail.Cascade.Lanes.SecretFlowMode(); got != "shadow" {
		t.Fatalf("default secret_flow lane = %q, want shadow", got)
	}
	if !sf.CredentialsEnabled() {
		t.Fatalf("credentials off by default")
	}
	if !sf.Reencodings {
		t.Fatalf("reencodings off by default")
	}
	if got := sf.SinkActionFor(false); got != "alert" {
		t.Fatalf("default sink action = %q, want alert", got)
	}
	if got := sf.SinkActionFor(true); got != "block" {
		t.Fatalf("strict sink action = %q, want block", got)
	}
	if sf.Memory.MaxLabeledPaths != 512 || sf.Memory.MaxValueDigests != 256 {
		t.Fatalf("memory caps = %+v, want 512/256", sf.Memory)
	}
}

// TestSecretFlowUpgradeFrom109 proves that a config written by 1.0.9 (which
// predates guardrail.secret_flow) loads with the shipped shadow defaults, so
// an upgrade from 1.0.9 never silently turns the feature on. The body mirrors
// the guardrail shape of testdata/upgrade/1.0.9/config.golden.yaml (whose
// @HOME@ path placeholders are not directly loadable) with no secret_flow key.
func TestSecretFlowUpgradeFrom109(t *testing.T) {
	raw := []byte(upgrade109Config)
	if strings.Contains(string(raw), "secret_flow") {
		t.Fatal("the 1.0.9 fixture must not name secret_flow")
	}
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
		t.Fatalf("the current release refuses a 1.0.9 config: %v", err)
	}
	cfg, err := LoadRuntimeV8FromBytes(filepath.Join(t.TempDir(), DefaultConfigName), raw)
	if err != nil {
		t.Fatalf("load 1.0.9 config: %v", err)
	}
	sf := cfg.Guardrail.SecretFlow
	if got := cfg.Guardrail.Cascade.Lanes.SecretFlowMode(); got != "shadow" || !sf.CredentialsEnabled() || sf.SinkActionFor(false) != "alert" {
		t.Fatalf("1.0.9 upgrade did not yield shadow/credentials/alert defaults: %+v", sf)
	}
}

// upgrade109Config is a config_version 9 config as 1.0.9 wrote it: a guardrail
// block with no secret_flow key. Pinned here as the upgrade fixture for the
// new key.
const upgrade109Config = `config_version: 9
guardrail:
  mode: action
  detection_strategy: regex_judge
observability: {}
`

// TestSecretFlowDefaultNeverBlocks: the schema and the Go validator both
// refuse sink_action.default = block (balanced defaults).
func TestSecretFlowDefaultNeverBlocks(t *testing.T) {
	raw := []byte("config_version: 9\nguardrail:\n  secret_flow:\n    sink_action:\n      default: block\n")
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil {
		t.Fatalf("schema accepted sink_action.default = block")
	}
	sf := SecretFlowConfig{SinkAction: SecretFlowSinkAction{Default: "block"}}
	if err := sf.Validate(); err == nil || !strings.Contains(err.Error(), "never blocks") {
		t.Fatalf("Validate() accepted default=block: %v", err)
	}
}

// TestSecretFlowValidate covers the Go validator cases.
func TestSecretFlowValidate(t *testing.T) {
	ok := []SecretFlowConfig{
		{},
		{SinkAction: SecretFlowSinkAction{Default: "alert", Strict: "block"}},
		{Memory: SecretFlowMemory{MaxLabeledPaths: 1000, MaxValueDigests: 1000}},
	}
	for i, c := range ok {
		if err := c.Validate(); err != nil {
			t.Fatalf("ok[%d] rejected: %v", i, err)
		}
	}
	bad := []SecretFlowConfig{
		{SinkAction: SecretFlowSinkAction{Strict: "warn"}},
		{Memory: SecretFlowMemory{MaxLabeledPaths: -1}},
		{Memory: SecretFlowMemory{MaxValueDigests: 1 << 30}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("bad[%d] accepted: %+v", i, c)
		}
	}
}
