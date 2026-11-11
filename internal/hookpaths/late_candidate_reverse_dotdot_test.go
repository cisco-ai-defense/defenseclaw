// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0641 review 10: the cleaned spelling of a dot-dot path can name a
// protected link that the kernel never opens. Here project/status is a link
// to a protected file while jump (a link to other/child) makes ../status
// open the ordinary other/status. The reading follows the kernel at every
// position of the step; the directly named protected link stays protected.
func TestGAP0641CleanedSpellingProtectedLinkIsNotReachedThroughLinkedParent(t *testing.T) {
	home, cwd, other := dotDotFixture(t)
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	if err := os.Remove(filepath.Join(cwd, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(other, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "status"), []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(cwd, "jump")
	t.Chdir(linked)
	// The reading that follows jump first opens the ordinary other/status.
	if got := readParentThroughLink(t, linked, "status"); got != "ordinary" {
		t.Fatalf("followed-link read %q", got)
	}
	// On Windows the cleaned spelling is a second reading (Win32 removes the
	// step from the text) and it opens the protected link, so a name is
	// ordinary only when both readings are: the rows that name the step are
	// protected there and ordinary elsewhere.
	viaStep := GradeNone
	if dotDotReadsLexically {
		if got := readParentOfText(t, linked, "status"); got != "protected-entry" {
			t.Fatalf("cleaned-spelling read %q", got)
		}
		viaStep = GradeNamed
	}
	for _, row := range []struct {
		name, command, dir string
		want               Grade
	}{
		{"leading parent", "cat ../status", linked, viaStep},
		{"dot then parent", "cat ./../status", linked, viaStep},
		{"absolute spelling", "cat " + linked + "/../status", linked, viaStep},
		{"option value", "grep --file=../status x", linked, viaStep},
		{"option value separate", "grep -f ../status x", linked, viaStep},
		{"step inside the operand", "cat jump/../status", cwd, viaStep},
		{"directly named protected link", "cat status", cwd, GradeNamed},
		{"directly named from a real parent", "cat plain/../status", cwd, GradeNamed},
	} {
		if got := LateCallGrade(row.command, row.dir, home); got != row.want {
			t.Errorf("%s: LateCallGrade(%q)=%s, want %s", row.name, row.command, got, row.want)
		}
	}
	if got := ProtectedReach(cwd+"/jump/../status", home, NewTargetMemo()); got != viaStep {
		t.Errorf("ProtectedReach of the ordinary physical file = %s, want %s", got, viaStep)
	}
	if got := ProtectedReach(cwd+"/status", home, NewTargetMemo()); got != GradeNamed {
		t.Errorf("ProtectedReach of the named link = %s, want Named", got)
	}
}
