// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func enrollmentUnits(manifest enterprisehooks.Manifest) string {
	units := []string{}
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			units = append(units, enterpriseHookEnrollmentUnit(target))
		}
	}
	sort.Strings(units)
	return strings.Join(units, ",")
}

// GAP-0790: the Guardian publishes the protected enrollment set from the
// manifest minus the failed targets that were never protected. Verify used
// to compare that set with the whole enabled manifest, so one skipped
// account (a link at its DefenseClaw folder that an administrator owns)
// failed the machine with "protected enrollment set is not exact" even
// though every other stage excused it. Verify now reads the same rule from
// the protection ledger, so what it expects is what the Guardian publishes.
func TestVerifyExpectsTheEnrollmentSetTheGuardianPublishesForASkippedAccount(t *testing.T) {
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "claudecode", SID: alice}, {Connector: "codex", SID: alice},
		{Connector: "claudecode", SID: bob}, {Connector: "codex", SID: bob},
	}}
	// The Guardian pass: the two rows of alice failed with the foreign-link
	// error and her ledger says she was never protected. The verify pass
	// excuses the same two rows.
	guardian := map[string]struct{}{}
	verify := map[string]struct{}{}
	for _, target := range manifest.Targets[:2] {
		if enterpriseHookFailedTargetUnenrolls(false, false) {
			guardian[enterpriseHookEnrollmentUnit(target)] = struct{}{}
		}
		enterpriseHookNoteExcusedUnenrolled(verify, target, false)
	}
	published := enrollmentUnits(enterpriseHookEnrollmentManifest(manifest, guardian))
	expected := enrollmentUnits(enterpriseHookEnrollmentManifest(manifest, verify))
	if published != "claudecode@S-1-5-21-1-2-3-1002,codex@S-1-5-21-1-2-3-1002" {
		t.Fatalf("the Guardian published %q, want only the other account", published)
	}
	if expected != published {
		t.Fatalf("verify expects %q, the Guardian publishes %q", expected, published)
	}
	// What verify compared before: the whole enabled manifest, which names
	// the skipped account the Guardian left out.
	if whole := enrollmentUnits(manifest); whole == published {
		t.Fatalf("the whole manifest %q equals the published set; the skipped account is not in the test", whole)
	}
}

// Benign twin: a skipped account an earlier release already protected keeps
// the enrollment the Guardian published for it, so verify still expects its
// SID, and a target that is not noted is expected like any other.
func TestVerifyKeepsExpectingAProtectedAccountEnrolled(t *testing.T) {
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "claudecode", SID: alice}, {Connector: "claudecode", SID: bob},
	}}
	verify := map[string]struct{}{}
	enterpriseHookNoteExcusedUnenrolled(verify, manifest.Targets[0], true)
	if len(verify) != 0 {
		t.Fatalf("a previously protected account was noted as unenrolled: %v", verify)
	}
	if got, want := enrollmentUnits(enterpriseHookEnrollmentManifest(manifest, verify)), enrollmentUnits(manifest); got != want {
		t.Fatalf("verify expects %q, want the whole enabled manifest %q", got, want)
	}
}
