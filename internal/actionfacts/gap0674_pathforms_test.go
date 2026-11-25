package actionfacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP0674WalkReadsOneFolderTheSameInEveryFormOfItsPath is
// substrate-1:GAP-0674's path-form test: a folder named in any form its
// platform allows is walked to the same files under the same bounds, so no
// form makes a second walk of a folder look like a different one, a walk
// that finds less, or one that costs more of the budget. The tree holds
// folders under long names (the Windows repro's 200-character names, whose
// paths pass 260 characters) with credentials files at two depths. The
// forms are credentialWalkPathForms: a trailing separator and a dot segment
// everywhere; on Windows also the drive letter in each case, forward slashes,
// the \\?\ prefix and a junction to the folder.
func TestGAP0674WalkReadsOneFolderTheSameInEveryFormOfItsPath(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("d", 200)
	files := []string{
		filepath.Join(root, ".env"),
		filepath.Join(root, long, long, ".env"),
		filepath.Join(root, long, "other", ".npmrc"),
	}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := credentialPathWalk(credentialWalkBudgetUnbounded(), root, root, credentialWalkFilter{}, credentialPathWalkBounds, credentialWalkRoomAll())
	if len(base.found) != len(files) || base.cut {
		t.Fatalf("walk of %s found %v cut %v, want the %d files and no cut", root, base.found, base.cut, len(files))
	}
	forms := credentialWalkPathForms(t, root)
	if len(forms) < 3 {
		t.Fatalf("only %d forms of the folder: %v", len(forms), forms)
	}
	for _, form := range forms {
		walk := credentialPathWalk(credentialWalkBudgetUnbounded(), form, form, credentialWalkFilter{}, credentialPathWalkBounds, credentialWalkRoomAll())
		if walk.used != base.used || walk.cut || len(walk.found) != len(base.found) {
			t.Errorf("form %q: used %+v cut %v found %d, want used %+v, no cut, %d found (the form of %q)", form, walk.used, walk.cut, len(walk.found), base.used, len(base.found), root)
			continue
		}
		for i, file := range walk.found {
			if !sameCredentialWalkFile(file, base.found[i]) {
				t.Errorf("form %q: found %q at %d, want the file %q", form, file, i, base.found[i])
			}
		}
	}
	// The resolve keys the folders it has walked by the folder as typed
	// (credentialWalkKey), so two forms of one folder in one call are two
	// walks: both are read, both within the call's one walk budget.
	slash := filepath.ToSlash(root)
	facts := Analyze(Input{Tool: "exec", Command: "grep -r KEY " + slash + " " + slash + "/./", CWD: root, ActiveHome: t.TempDir()})
	if caps := facts.CredentialPathReadCaps(context.Background()); caps.Any() {
		t.Fatalf("two forms of one folder in one call are a cap of the resolve: %v", caps)
	}
	if got := len(facts.CredentialPathReads()); got == 0 {
		t.Fatalf("the walk of the folder read nothing: %v", facts.CredentialPathReads())
	}
}

// sameCredentialWalkFile reports one file named in two forms of its path.
func sameCredentialWalkFile(a, b string) bool {
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}
