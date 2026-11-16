// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
)

// GAP-0564, #1201: a run that refused the submitted config labels the
// running deployment's warnings from the given index on, keeps the codes
// that describe the refusal itself, never labels a warning twice, and
// labels the policy line too.
func TestLabelRunningDeployment(t *testing.T) {
	r := New("ensure", "standalone", "windows", "1.0.0")
	r.AddWarning("before", "added before the host was described")
	r.AddWarning("security_incomplete", "security is not complete: the guardian is not ready")
	r.AddWarning("health_not_checked", "this request was refused before any health check ran")
	r.AddWarning("rule_pack_readable_by_users", RunningDeploymentPrefix+"already labelled")
	r.LabelRunningDeployment(1, "health_not_checked")
	r.LabelRunningDeployment(1, "health_not_checked")
	want := []string{
		"added before the host was described",
		RunningDeploymentPrefix + "security is not complete: the guardian is not ready",
		"this request was refused before any health check ran",
		RunningDeploymentPrefix + "already labelled",
	}
	for i, warning := range r.Warnings {
		if warning.Message != want[i] {
			t.Fatalf("warning %d = %q, want %q", i, warning.Message, want[i])
		}
	}
	if !r.ConfigRefused {
		t.Fatal("the refused run is not marked")
	}
	r.Policy = &PolicyState{EffectiveDigest: "sha256:00"}
	if line := r.PolicyLine(); !strings.HasPrefix(line, "running policy (the refused config changed nothing)") {
		t.Fatalf("policy line = %q", line)
	}
	var nilResult *Result
	nilResult.LabelRunningDeployment(0)
}
