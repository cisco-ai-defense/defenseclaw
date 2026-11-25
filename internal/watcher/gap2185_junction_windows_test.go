// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A watch root that is a junction, or that is not made yet below one, is
// refused as a linked root, as a symbolic link is (rel-1-0-10:GAP-2185).
func TestGAP2185WatchRootThroughAJunctionIsRefused(t *testing.T) {
	base := gap2185Base(t)
	outside := filepath.Join(base, "outside", "skills")
	plain := filepath.Join(base, "plain", "skills")
	for _, dir := range []string{outside, plain} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	junction := filepath.Join(base, "skills-junction")
	gap2185Junction(t, junction, outside)
	if err := checkRootLinkRoute(junction); err == nil {
		t.Error("checkRootLinkRoute(junction root) = nil; want a linked-root refusal")
	}
	if err := checkRootLinkRoute(filepath.Join(junction, "not-yet")); err == nil {
		t.Error("checkRootLinkRoute(missing root below a junction) = nil; want a linked-root refusal")
	}
	if got, err := trustedWalkRoot(junction); err == nil {
		t.Errorf("trustedWalkRoot(junction root) = %q, nil; want a linked-root refusal", got)
	}
	if err := unlinkedSkillTreePath(junction, junction); err == nil {
		t.Error("unlinkedSkillTreePath(junction root) = nil; want a linked-root refusal")
	}
	if err := checkRootLinkRoute(plain); err != nil {
		t.Errorf("checkRootLinkRoute(plain root) = %v; want nil", err)
	}
	if got, err := trustedWalkRoot(plain); err != nil || got != plain {
		t.Errorf("trustedWalkRoot(plain root) = %q, %v; want %q", got, err, plain)
	}
}

// A path that is a junction into a folder of a held copy is inside the copy,
// so the hold stands for it. A path that passes a junction in the middle to
// an admitted copy is outside every held copy, so the hold is set aside for
// it (rel-1-0-10:GAP-2185).
func TestGAP2185PolicyHoldFollowsJunctions(t *testing.T) {
	root, held, admitted := heldAndAdmittedForTest(t)
	if err := os.MkdirAll(filepath.Join(held, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	toHeld := filepath.Join(root, "to-held-scripts")
	gap2185Junction(t, toHeld, filepath.Join(held, "scripts"))
	toAdmitted := filepath.Join(root, "to-admitted")
	gap2185Junction(t, toAdmitted, admitted)
	entry := policyHoldEntryFor(held)
	if holdIgnored(entry, toHeld) {
		t.Error("a junction into the held copy was let through")
	}
	if !holdIgnored(entry, filepath.Join(toAdmitted, "SKILL.md")) {
		t.Error("a file of the admitted copy, named through a junction, was held")
	}
	if holdIgnored(entry, filepath.Join(held, "SKILL.md")) {
		t.Error("the held file was let through")
	}
}

// A watched root that is a junction, or below one, is not mapped to the folder
// behind it (rel-1-0-10:GAP-2185).
func TestGAP2185ResolvedRootOfDoesNotMapARootThroughAJunction(t *testing.T) {
	base := gap2185Base(t)
	outside := filepath.Join(base, "outside", "skills")
	if err := os.MkdirAll(filepath.Join(outside, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "skills-junction")
	gap2185Junction(t, junction, outside)
	w := &InstallWatcher{cfg: &config.Config{}}
	if got, ok := w.resolvedRootOf(junction); ok {
		t.Errorf("resolvedRootOf(junction root) = %q, true; want not mapped", got)
	}
	if got, ok := w.resolvedRootOf(filepath.Join(junction, "inner")); ok {
		t.Errorf("resolvedRootOf(root below a junction) = %q, true; want not mapped", got)
	}
}

func gap2185Base(t *testing.T) string {
	t.Helper()
	base, err := winpath.EvalLinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func gap2185Junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}
