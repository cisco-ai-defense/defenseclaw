// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestStableFindingStateIdentityIsScopedAndCrossPlatformStable(t *testing.T) {
	line := 17
	base := Finding{
		Scanner: "CodeGuard", RuleID: "CG-001", Location: `C:\work\repo\main.go:17`,
		LineNumber: &line, EvidenceSummary: "matched bytes",
	}
	windows := StableFindingStateIdentity("CodeGuard", "code", `C:\work\repo`, base)
	unixFinding := base
	unixFinding.Location = "C:/work/repo/main.go:17"
	unix := StableFindingStateIdentity("codeguard", "code", "C:/work/./repo/", unixFinding)
	fileAlias := StableFindingStateIdentity("codeguard", "file", "C:/work/repo", unixFinding)
	if windows.Fingerprint != unix.Fingerprint || windows.NormalizedTarget != "c:/work/repo" ||
		windows.FilePath != `C:\work\repo\main.go` ||
		windows.NormalizedFilePath != "c:/work/repo/main.go" || windows.LineNumber != line {
		t.Fatalf("cross-platform identity drifted: windows=%+v unix=%+v", windows, unix)
	}
	if fileAlias.Fingerprint != unix.Fingerprint {
		t.Fatalf("code/file target-type alias drifted: code=%+v file=%+v", unix, fileAlias)
	}
	if got := NormalizeFindingStateTarget(`\\server\share\dir`); got != "//server/share/dir" {
		t.Fatalf("UNC target normalization=%q", got)
	}
	if len(windows.Fingerprint) != 64 || len(windows.ContentDigest) != 64 {
		t.Fatalf("identity digests are not full SHA-256 values: %+v", windows)
	}

	checks := map[string]FindingStateIdentity{
		"scope scanner": StableFindingStateIdentity("other", "code", `C:\work\repo`, base),
		"target type":   StableFindingStateIdentity("CodeGuard", "plugin", `C:\work\repo`, base),
		"target":        StableFindingStateIdentity("CodeGuard", "code", `C:\work\other`, base),
	}
	changed := base
	changed.RuleID = "CG-002"
	checks["rule"] = StableFindingStateIdentity("CodeGuard", "code", `C:\work\repo`, changed)
	changed = base
	changed.EvidenceSummary = "different matched bytes"
	checks["content"] = StableFindingStateIdentity("CodeGuard", "code", `C:\work\repo`, changed)
	changed = base
	changed.Scanner = "different-detector"
	checks["finding scanner"] = StableFindingStateIdentity("CodeGuard", "code", `C:\work\repo`, changed)
	for dimension, identity := range checks {
		if identity.Fingerprint == windows.Fingerprint {
			t.Errorf("%s did not scope the finding identity", dimension)
		}
	}
}

func TestStableFindingStateIdentityPrefersEvidenceAndStructuredLine(t *testing.T) {
	line := 9
	finding := Finding{
		RuleID: "rule", Location: "src/file.go:123", LineNumber: &line,
		EvidenceSummary: "evidence", Description: "description",
	}
	first := StableFindingStateIdentity("scanner", "code", "target", finding)
	finding.Description = "presentation-only change"
	second := StableFindingStateIdentity("scanner", "code", "target", finding)
	if first.Fingerprint != second.Fingerprint || first.LineNumber != line || first.FilePath != "src/file.go:123" {
		t.Fatalf("presentation text or location suffix overrode canonical evidence/line: first=%+v second=%+v", first, second)
	}

	finding.EvidenceSummary = "<redacted-sensitive len=20>"
	finding.ContentFingerprint = "0123abcd"
	first = StableFindingStateIdentity("scanner", "code", "target", finding)
	finding.ContentFingerprint = "9876fedc"
	second = StableFindingStateIdentity("scanner", "code", "target", finding)
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("keyed content identity did not distinguish equal-shape redacted evidence")
	}
}

func TestStableFindingStateIdentityPreservesAmbiguousNumericFilenameSuffix(t *testing.T) {
	t.Parallel()
	for _, location := range []string{"/work/payload:17", `C:17`} {
		identity := StableFindingStateIdentity(
			"scanner",
			"code",
			"target",
			Finding{RuleID: "rule", Location: location, EvidenceSummary: "evidence"},
		)
		if identity.FilePath != location || identity.LineNumber != 0 {
			t.Errorf("ambiguous location %q was reinterpreted: %+v", location, identity)
		}
	}

	line := 17
	filename := StableFindingStateIdentity(
		"scanner",
		"code",
		"target",
		Finding{RuleID: "rule", Location: "/work/payload:17", EvidenceSummary: "evidence"},
	)
	structured := StableFindingStateIdentity(
		"scanner",
		"code",
		"target",
		Finding{
			RuleID: "rule", Location: "/work/payload:17", LineNumber: &line,
			EvidenceSummary: "evidence",
		},
	)
	if structured.FilePath != "/work/payload" || structured.LineNumber != line {
		t.Fatalf("explicit line was not normalized: %+v", structured)
	}
	if filename.Fingerprint == structured.Fingerprint {
		t.Fatal("numeric filename and explicit source line collapsed to one identity")
	}
}

func TestFindingLifecycleDeltaIndexesOccurrenceEmissions(t *testing.T) {
	delta := FindingLifecycleDelta{
		Managed: true,
		Observations: []FindingLifecycleObservation{
			{OccurrenceID: "new", Status: FindingLifecycleNew},
			{OccurrenceID: "repeated", Status: FindingLifecycleRepeated},
			{OccurrenceID: "updated", Status: FindingLifecycleUpdated},
		},
	}
	delta.IndexOccurrenceEmissions()

	for occurrenceID, want := range map[string]bool{
		"new": true, "repeated": false, "updated": true, "unknown": false,
	} {
		if got := delta.ShouldEmitOccurrence(occurrenceID); got != want {
			t.Errorf("ShouldEmitOccurrence(%q) = %t, want %t", occurrenceID, got, want)
		}
	}
	if delta.emitByOccurrence == nil {
		t.Fatal("occurrence emission index was not retained")
	}
}

func TestFindingLifecycleDeltaUnindexedFallbackPreservesPriorBehavior(t *testing.T) {
	managed := &FindingLifecycleDelta{
		Managed: true,
		Observations: []FindingLifecycleObservation{
			{OccurrenceID: "reopened", Status: FindingLifecycleReopened},
		},
	}
	if !managed.ShouldEmitOccurrence("reopened") {
		t.Fatal("unindexed managed delta did not emit a reopened occurrence")
	}
	if managed.emitByOccurrence != nil {
		t.Fatal("read-only fallback unexpectedly initialized an emission index")
	}
	managed.Observations[0].Status = FindingLifecycleRepeated
	if managed.ShouldEmitOccurrence("reopened") {
		t.Fatal("unindexed fallback did not reflect a later observation edit")
	}

	if !(*FindingLifecycleDelta)(nil).ShouldEmitOccurrence("any") {
		t.Fatal("nil lifecycle delta must preserve emit-every-occurrence behavior")
	}
	if !(&FindingLifecycleDelta{}).ShouldEmitOccurrence("any") {
		t.Fatal("unmanaged lifecycle delta must preserve emit-every-occurrence behavior")
	}
}
