// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"strings"
	"testing"
)

// TestMergeVerdictDispatch_OpensourceParity is the G3 canary. It locks
// the opensource merge behavior against future edits: with
// managedMode=false, g.mergeVerdict must return exactly what the
// standalone mergeVerdicts function returns on identical inputs. If a
// future change accidentally routes non-managed traffic through
// mergeVerdictsManaged, this test fails.
func TestMergeVerdictDispatch_OpensourceParity(t *testing.T) {
	cases := []struct {
		name  string
		local *ScanVerdict
		cisco *ScanVerdict
	}{
		{"both nil", nil, nil},
		{"local nil / cisco alert", nil, &ScanVerdict{Action: "alert", Severity: "MEDIUM", Reason: "aid", Scanner: "ai-defense"}},
		{"cisco nil / local block", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "regex", Scanner: "local-pattern"}, nil},
		{
			"tie on HIGH — local wins in opensource",
			&ScanVerdict{Action: "block", Severity: "HIGH", Reason: "regex hit", Findings: []string{"r1"}, Scanner: "local-pattern"},
			&ScanVerdict{Action: "block", Severity: "HIGH", Reason: "aid hit", Findings: []string{"c1"}, Scanner: "ai-defense"},
		},
		{
			"cisco allow / local alert — local wins in opensource",
			&ScanVerdict{Action: "alert", Severity: "MEDIUM", Reason: "regex", Findings: []string{"r1"}},
			&ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"},
		},
	}
	g := &GuardrailInspector{managedMode: false}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDispatch := g.mergeVerdict(cloneVerdict(tc.local), cloneVerdict(tc.cisco))
			gotDirect := mergeVerdicts(cloneVerdict(tc.local), cloneVerdict(tc.cisco))
			if !reflect.DeepEqual(gotDispatch, gotDirect) {
				t.Fatalf("dispatch drift on %q:\ndispatch = %#v\ndirect   = %#v", tc.name, gotDispatch, gotDirect)
			}
		})
	}
}

// TestMergeVerdictsManaged_CloudAllowOverridesLocalAlert asserts §6b
// rule 2: when cloud says allow, managed mode drops local alert.
func TestMergeVerdictsManaged_CloudAllowOverridesLocalAlert(t *testing.T) {
	local := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Reason: "regex triage", Findings: []string{"r1"}, Scanner: "local-pattern"}
	cisco := &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"}

	got := mergeVerdictsManaged(cloneVerdict(local), cloneVerdict(cisco))
	if got == nil {
		t.Fatal("expected non-nil merged verdict")
	}
	if got.Action != "allow" {
		t.Errorf("Action = %q, want allow (cloud allow must dominate in managed mode)", got.Action)
	}
	if got.Severity != "NONE" {
		t.Errorf("Severity = %q, want NONE", got.Severity)
	}
	// Local findings must survive for the audit trail.
	if !containsString(got.Findings, "r1") {
		t.Errorf("local finding r1 dropped from Findings: %v", got.Findings)
	}
	// And local reason must be visible somewhere for operators reviewing the trail.
	if !strings.Contains(got.Reason, "regex triage") {
		t.Errorf("local reason lost from Reason: %q", got.Reason)
	}
}

// TestMergeVerdictsManaged_CloudBlockBeatsLocalTie asserts §6b rule 1:
// on tie severity, cloud wins so the AID reason / action are surfaced.
func TestMergeVerdictsManaged_CloudBlockBeatsLocalTie(t *testing.T) {
	local := &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "matched: TRUST-IGNORE:...", Findings: []string{"r1"}, Scanner: "local-pattern"}
	cisco := &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "Cisco AI Defense: Prompt Injection", Findings: []string{"Prompt Injection"}, Scanner: "ai-defense"}

	got := mergeVerdictsManaged(cloneVerdict(local), cloneVerdict(cisco))
	if got == nil {
		t.Fatal("expected non-nil merged verdict")
	}
	if got.Action != "block" {
		t.Errorf("Action = %q, want block", got.Action)
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", got.Severity)
	}
	// On a cloud-driven block, the enforceable Reason surfaced to the
	// agent must be the CLOUD reason alone. Local pattern is
	// telemetry-only in managed mode and its "matched: <RULE_ID>:..."
	// text (a) collides with the cloud reason on the user surface and
	// (b) gets aggressively scrubbed by redaction downstream. See the
	// "Rule 3" comment in mergeVerdictsManaged.
	if got.Reason != "Cisco AI Defense: Prompt Injection" {
		t.Errorf("Reason = %q, want exactly the cloud reason (local reason must be dropped on cloud-driven block)", got.Reason)
	}
	// Both findings must accumulate — the local finding is still
	// recorded for audit even though the Reason drops its text.
	if !containsString(got.Findings, "r1") || !containsString(got.Findings, "Prompt Injection") {
		t.Errorf("expected both findings to accumulate, got %v", got.Findings)
	}
}

// TestMergeVerdictsManaged_NilCloudLeavesLocalUnchanged: managed mode
// must not fabricate cloud clearance when the cloud didn't respond.
func TestMergeVerdictsManaged_NilCloudLeavesLocalUnchanged(t *testing.T) {
	local := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Reason: "regex", Findings: []string{"r1"}, Scanner: "local-pattern"}

	got := mergeVerdictsManaged(cloneVerdict(local), nil)
	if got == nil {
		t.Fatal("expected non-nil merged verdict")
	}
	if got.Action != "alert" {
		t.Errorf("Action = %q, want alert (local unchanged when cloud is nil)", got.Action)
	}
	if got.Severity != "MEDIUM" {
		t.Errorf("Severity = %q, want MEDIUM", got.Severity)
	}
	if len(got.ScannerSources) != 1 || got.ScannerSources[0] != "local-pattern" {
		t.Errorf("ScannerSources = %v, want [local-pattern]", got.ScannerSources)
	}
}

// TestMergeVerdictsManaged_CloudBlockOverridesLowerLocal exercises the
// "cloud says block, local says allow" case — cloud must win.
func TestMergeVerdictsManaged_CloudBlockOverridesLowerLocal(t *testing.T) {
	local := &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "local-pattern"}
	cisco := &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "aid", Findings: []string{"Prompt Injection"}, Scanner: "ai-defense"}

	got := mergeVerdictsManaged(cloneVerdict(local), cloneVerdict(cisco))
	if got.Action != "block" {
		t.Errorf("Action = %q, want block", got.Action)
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", got.Severity)
	}
}

// TestMergeVerdictDispatch_ManagedDemotesLocalOnlyBlockToAlert locks in
// the posture we adopted for managed_enterprise: local pattern findings
// are telemetry-only. A local-only "block" verdict flowing through the
// dispatch must come out as "alert" so the sole source of enforceable
// block verdicts is the AID cloud (cisco_ai_defense).
//
// Reason and Findings are preserved so the audit trail records what
// local pattern hit — only Action is capped.
func TestMergeVerdictDispatch_ManagedDemotesLocalOnlyBlockToAlert(t *testing.T) {
	local := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "matched: dangerous command",
		Findings: []string{"cmd-inject"},
		Scanner:  "local-pattern",
	}
	g := &GuardrailInspector{managedMode: true}

	// nil cisco simulates "AID call skipped or unavailable"; local
	// block would previously enforce on its own. In managed mode we
	// want it demoted.
	got := g.mergeVerdict(cloneVerdict(local), nil)
	if got == nil {
		t.Fatal("expected non-nil merged verdict")
	}
	if got.Action != "alert" {
		t.Errorf("Action = %q, want alert (managed mode demotes local-only block)", got.Action)
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH (severity preserved for audit)", got.Severity)
	}
	if !containsString(got.Findings, "cmd-inject") {
		t.Errorf("Findings dropped local finding: %v", got.Findings)
	}
	if got.Reason == "" {
		t.Errorf("Reason must be preserved for audit trail")
	}
}

// TestMergeVerdictDispatch_ManagedPreservesCloudBlock: cloud-driven
// blocks still enforce. The demoter only touches local-only verdicts.
func TestMergeVerdictDispatch_ManagedPreservesCloudBlock(t *testing.T) {
	local := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "regex",
		Findings: []string{"local1"},
		Scanner:  "local-pattern",
	}
	cisco := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "Cisco AI Defense: Prompt Injection",
		Findings: []string{"Prompt Injection"},
		Scanner:  "ai-defense",
	}
	g := &GuardrailInspector{managedMode: true}

	got := g.mergeVerdict(cloneVerdict(local), cloneVerdict(cisco))
	if got == nil {
		t.Fatal("expected non-nil merged verdict")
	}
	if got.Action != "block" {
		t.Errorf("Action = %q, want block (cloud block must survive local demotion)", got.Action)
	}
	if !strings.Contains(got.Reason, "Cisco AI Defense") {
		t.Errorf("Reason = %q, want to include cloud reason", got.Reason)
	}
}

// TestMergeVerdictDispatch_OpensourceLocalBlockStillEnforces: the
// demoter MUST NOT fire outside managed mode.
func TestMergeVerdictDispatch_OpensourceLocalBlockStillEnforces(t *testing.T) {
	local := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "regex",
		Findings: []string{"cmd-inject"},
		Scanner:  "local-pattern",
	}
	g := &GuardrailInspector{managedMode: false}

	got := g.mergeVerdict(cloneVerdict(local), nil)
	if got.Action != "block" {
		t.Errorf("Action = %q, want block (opensource must NOT demote)", got.Action)
	}
}

// TestNewGuardrailInspector_NilInspectorInterface is the G1 canary. It
// verifies that constructing an inspector with a nil *CiscoInspectClient
// leaves g.ciscoClient as a nil INTERFACE (not a typed-nil interface
// wrapping a nil pointer), so downstream `g.ciscoClient != nil` guards
// still short-circuit correctly.
func TestNewGuardrailInspector_NilInspectorInterface(t *testing.T) {
	g := NewGuardrailInspector("remote", nil, nil, "")
	if g.ciscoClient != nil {
		t.Fatalf("g.ciscoClient must be a nil interface when NewGuardrailInspector is called with a nil *CiscoInspectClient; got %#v (interface holds concrete type %T)",
			g.ciscoClient, g.ciscoClient)
	}
}

func cloneVerdict(v *ScanVerdict) *ScanVerdict {
	if v == nil {
		return nil
	}
	c := *v
	if v.Findings != nil {
		c.Findings = append([]string(nil), v.Findings...)
	}
	if v.ScannerSources != nil {
		c.ScannerSources = append([]string(nil), v.ScannerSources...)
	}
	return &c
}
