// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// The alignment lane is opt-in: off unless an admin sets it, and a value
// set in YAML is the value the gateway resolves.
func TestCascadeAlignmentLaneLoadsItsValues(t *testing.T) {
	if got := loadCascadeDoc(t, "guardrail:\n  enabled: true\n").ResolveCascade("codex").LaneMode(CascadeLaneAlignment); got != CascadeLaneOff {
		t.Fatalf("default = %q, want off", got)
	}
	for _, v := range []string{"shadow", "alert", "block"} {
		cfg := loadCascadeDoc(t, "guardrail:\n  cascade:\n    lanes:\n      alignment: "+v+"\n")
		if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
			t.Fatalf("%s: invalid: %s", v, inv.Message())
		}
		if got := cfg.ResolveCascade("codex").LaneMode(CascadeLaneAlignment); got != v {
			t.Fatalf("%s: resolved %q", v, got)
		}
	}
	// Exact values: a different spelling never switches the lane on.
	for _, v := range []string{"Alert", "BLOCK", "shadow "} {
		c := &Config{}
		c.Guardrail.Cascade.Lanes = map[string]string{CascadeLaneAlignment: v}
		if err := c.ValidateCascade(false); err == nil {
			t.Fatalf("lanes.alignment %q accepted", v)
		}
	}
	cfg := loadCascadeDoc(t, "guardrail:\n  cascade:\n    lanes:\n      alignment: on\n")
	if inv := cfg.Guardrail.Cascade.Invalid(); inv == nil || !strings.Contains(inv.Error, "off, shadow, alert, block") {
		t.Fatalf("on accepted or unclear: %+v", inv)
	}
	if got := cfg.ResolveCascade("codex").LaneMode(CascadeLaneAlignment); got != CascadeLaneOff {
		t.Fatalf("invalid cascade resolved alignment %q, want the default off", got)
	}
}

// A managed admin locks lanes.alignment: a connector or profile scope that
// sets it does not decide (the top-level value applies), the value is named
// as ignored, and writers refuse the document (GAP-0580 runtime locks).
func TestCascadeAlignmentLaneAdminLock(t *testing.T) {
	for _, lock := range []string{"lanes.alignment", "lanes", "*"} {
		body := "guardrail:\n  cascade:\n    lanes:\n      alignment: block\n    admin:\n      locked: [\"" + lock + "\"]\n" +
			"  connectors:\n    codex:\n      cascade:\n        lanes:\n          alignment: \"off\"\n"
		cfg := loadCascadeDoc(t, body)
		if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
			t.Fatalf("lock %s: the whole cascade fell back: %s", lock, inv.Message())
		}
		if CascadeCandidateError(cfg) == nil {
			t.Fatalf("lock %s: writers would accept a connector override of a locked lane", lock)
		}
		found := false
		for _, ig := range cfg.Guardrail.Cascade.Ignored() {
			if ig.Path == "guardrail.connectors.codex.cascade.lanes.alignment" {
				found = true
			}
		}
		if !found {
			t.Fatalf("lock %s: the override is not named as ignored: %+v", lock, cfg.Guardrail.Cascade.Ignored())
		}
		if got := cfg.ResolveCascade("codex").LaneMode(CascadeLaneAlignment); got != CascadeLaneBlock {
			t.Fatalf("lock %s: codex = %q, want the locked top-level block", lock, got)
		}
	}
	// The same document without the lock is valid and the connector scope wins.
	cfg := loadCascadeDoc(t, "guardrail:\n  cascade:\n    lanes:\n      alignment: block\n"+
		"  connectors:\n    codex:\n      cascade:\n        lanes:\n          alignment: \"off\"\n")
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("unlocked override refused: %s", inv.Message())
	}
	if got := cfg.ResolveCascade("codex").LaneMode(CascadeLaneAlignment); got != CascadeLaneOff {
		t.Fatalf("codex = %q, want off", got)
	}
	if got := cfg.ResolveCascade("claudecode").LaneMode(CascadeLaneAlignment); got != CascadeLaneBlock {
		t.Fatalf("claudecode = %q, want block", got)
	}
}
