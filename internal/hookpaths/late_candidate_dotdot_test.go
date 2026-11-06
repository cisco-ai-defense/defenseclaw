// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// dotDotFixture lays out a protected state file, an ordinary directory with
// an ordinary "status" and a linked directory whose parent holds a link
// named "status" to the protected file. The kernel follows "jump" before it
// applies "..", so jump/../status opens the protected file while the clean
// spelling status is ordinary.
func dotDotFixture(t *testing.T) (home, cwd, other string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	cwd = filepath.Join(root, "project")
	other = filepath.Join(root, "other")
	state := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{cwd, filepath.Join(other, "child"), filepath.Join(cwd, "plain"), state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(state, "entry")
	for path, data := range map[string]string{protected: "protected-entry",
		filepath.Join(cwd, "status"): "ordinary"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(protected, filepath.Join(other, "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "child"), filepath.Join(cwd, "jump")); err != nil {
		t.Fatal(err)
	}
	return home, cwd, other
}

// GAP-0641 review 8: a directory link before a dot-dot step is followed by
// the kernel first. Cleaning the spelling must not clear a protected link
// that the physical path reaches; the clean twin stays ordinary.
func TestGAP0641LinkBeforeDotDotKeepsProtectedLinkNamed(t *testing.T) {
	home, cwd, other := dotDotFixture(t)
	if data, err := os.ReadFile(cwd + "/jump/../status"); err != nil || string(data) != "protected-entry" {
		t.Fatalf("kernel read %q err=%v", data, err)
	}
	for _, row := range []struct {
		name, command string
		want          Grade
	}{
		{"linked directory then dot-dot", "cat jump/../status", GradeNamed},
		{"absolute spelling", "cat " + cwd + "/jump/../status", GradeNamed},
		{"option value spelling", "grep -f jump/../status x", GradeNamed},
		{"clean twin", "cat status", GradeNone},
		{"real directory then dot-dot", "cat plain/../status", GradeNone},
		{"plain parent step", "cat ../project/status", GradeNone},
	} {
		if got := LateCallGrade(row.command, cwd, home); got != row.want {
			t.Errorf("%s: LateCallGrade(%q)=%s, want %s", row.name, row.command, got, row.want)
		}
	}
	if got := ProtectedReach(cwd+"/jump/../status", home, NewTargetMemo()); got != GradeNamed {
		t.Errorf("ProtectedReach through a linked directory = %s, want Named", got)
	}
	if got := ProtectedReach(cwd+"/plain/../status", home, NewTargetMemo()); got != GradeNone {
		t.Errorf("ProtectedReach through a real directory = %s, want None", got)
	}

	// A linked directory to an ordinary place stays ordinary.
	if err := os.WriteFile(filepath.Join(other, "plain-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LateCallGrade("cat jump/../plain-file", cwd, home); got != GradeNone {
		t.Errorf("ordinary file beside a linked directory = %s, want None", got)
	}
}

// The process-relative form: /proc/self/cwd is the cwd of the process that
// opens the path, so a dot-dot step after it is not the hook own reading.
func TestGAP0641ProcessCwdBeforeDotDotIsNotOrdinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/cwd is Linux only")
	}
	home, cwd, _ := dotDotFixture(t)
	t.Chdir(cwd)
	if got := LateCallGrade("cat /proc/self/cwd/../status", cwd, home); got == GradeNone {
		t.Errorf("process-relative dot-dot read as ordinary")
	}
	if got := ProtectedReach("/proc/self/cwd/../status", home, NewTargetMemo()); got == GradeNone {
		t.Errorf("ProtectedReach cleared a process-relative dot-dot")
	}
	if got := LateCallGrade("cat /proc/self/status", cwd, home); got != GradeNone {
		t.Errorf("ordinary /proc/self/status = %s, want None", got)
	}
}
