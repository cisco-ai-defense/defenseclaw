// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-0476: an undo forgets only the writing steps of the artifact chains
// about reverted files; every other step of the same event stays, and the
// stored result is still read as a repeat of the original observation.
func TestGAP0476ForgetKeepsOtherSteps(t *testing.T) {
	d, _ := ToolChainPOSIXPathDigest("/work/app/dl.sh")
	other := strings.Repeat("b", 64)
	direct, _ := ToolChainIndexByID(ToolChainDownloadThenExecuteSameArtifact)
	secret, _ := ToolChainIndexByID(ToolChainSecretReadThenEgress)
	download, _ := ToolChainStepMask(ToolChainDownloadThenExecuteSameArtifact, 1)
	run, _ := ToolChainStepMask(ToolChainDownloadThenExecuteSameArtifact, 2)
	read, _ := ToolChainStepMask(ToolChainSecretReadThenEgress, 1)
	p := ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: download | read, EnforcementStepMask: read}
	p.EnforcementJoinDigests[direct] = d
	p.EnforcementJoinDigests[secret] = other
	if err := ValidateToolChainProjection(p); err != nil {
		t.Fatal(err)
	}
	events := []ToolChainWindowEvent{{SemanticEventID: "e1", Sequence: 1, Projection: p}}
	out := ForgetToolChainArtifacts(events, func(digest string, _ ToolChainWindowEvent) bool { return digest == d })
	got, ok := out["e1"]
	if !ok || got.DetectionStepMask != read || got.EnforcementStepMask != read ||
		got.EnforcementJoinDigests[direct] != "" || got.EnforcementJoinDigests[secret] != other {
		t.Fatalf("forgot %+v", got)
	}
	if !ToolChainProjectionForgotten(got, p) || ToolChainProjectionForgotten(p, got) {
		t.Fatal("forgotten-from is not one way")
	}
	// A secret read is never a write of an artifact: taking it out is not
	// a forgotten version.
	noRead := p
	noRead.DetectionStepMask, noRead.EnforcementStepMask, noRead.EnforcementJoinDigests[secret] = download, 0, ""
	if ToolChainProjectionForgotten(noRead, p) {
		t.Fatal("a dropped secret read passes as forgotten")
	}
	// Not reverted, or a run (not a write): nothing changes.
	if out := ForgetToolChainArtifacts(events, func(string, ToolChainWindowEvent) bool { return false }); len(out) != 0 {
		t.Fatalf("changed without a reverted file: %v", out)
	}
	r := ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: run}
	r.EnforcementJoinDigests[direct] = d
	if out := ForgetToolChainArtifacts([]ToolChainWindowEvent{{SemanticEventID: "e2", Sequence: 2, Projection: r}},
		func(string, ToolChainWindowEvent) bool { return true }); len(out) != 0 {
		t.Fatalf("a run was forgotten: %v", out)
	}
}
