package hookpaths

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestGAP0641FixedPIDProcCWDOrdinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	project := filepath.Join(root, "project")
	runner := filepath.Join(root, "runner", "child")
	for _, dir := range []string{filepath.Dir(protected), project, runner} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	testenv.SymlinkOrSkip(t, protected, filepath.Join(project, "status"))
	pidPath := fmt.Sprintf("/proc/%d/cwd", os.Getpid())
	testenv.SymlinkOrSkip(t, pidPath, filepath.Join(project, "jump"))
	testenv.SymlinkOrSkip(t, "jump", filepath.Join(project, "chain"))
	t.Chdir(runner)
	for _, path := range []string{
		pidPath + "/../status",
		filepath.Join(project, "jump") + "/../status",
		filepath.Join(project, "chain") + "/../status",
	} {
		data, err := exec.Command("cat", path).Output()
		if err != nil || string(data) != "ordinary" {
			t.Fatalf("child read %q = %q, %v", path, data, err)
		}
		if got := ProtectedReach(path, home, NewTargetMemo()); got != GradeNone {
			t.Errorf("ordinary fixed-PID path %q grade=%s, want None", path, got)
		}
		if got := LateCallGrade("cat "+path, runner, home); got != GradeNone {
			t.Errorf("ordinary fixed-PID command %q grade=%s, want None", path, got)
		}
	}
	if got := ProtectedReach(filepath.Join(project, "status"), home, NewTargetMemo()); got != GradeNamed {
		t.Errorf("direct protected link grade=%s, want Named", got)
	}
}

func TestGAP0641FixedPIDProcFDOrdinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	project := filepath.Join(root, "project")
	ordinaryDir := filepath.Join(root, "ordinary", "child")
	for _, dir := range []string{filepath.Dir(protected), project, ordinaryDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ordinary", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinaryDir, "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	testenv.SymlinkOrSkip(t, protected, filepath.Join(project, "status"))
	dir, err := os.Open(ordinaryDir)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), dir.Fd())
	testenv.SymlinkOrSkip(t, fdPath, filepath.Join(project, "jump"))
	testenv.SymlinkOrSkip(t, "jump", filepath.Join(project, "chain"))
	for _, path := range []string{
		fdPath + "/status",
		fdPath + "/../status",
		filepath.Join(project, "jump") + "/../status",
		filepath.Join(project, "chain") + "/../status",
	} {
		data, err := exec.Command("cat", path).Output()
		if err != nil || string(data) != "ordinary" {
			t.Fatalf("child read %q = %q, %v", path, data, err)
		}
		if got := ProtectedReach(path, home, NewTargetMemo()); got != GradeNone {
			t.Errorf("ordinary fixed-PID fd path %q grade=%s, want None", path, got)
		}
		if got := LateCallGrade("cat "+path, project, home); got != GradeNone {
			t.Errorf("ordinary fixed-PID fd command %q grade=%s, want None", path, got)
		}
	}
	if got := ProtectedReach(filepath.Join(project, "status"), home, NewTargetMemo()); got != GradeNamed {
		t.Errorf("direct protected link grade=%s, want Named", got)
	}
	if err := os.Remove(filepath.Join(root, "ordinary", "status")); err != nil {
		t.Fatal(err)
	}
	testenv.SymlinkOrSkip(t, protected, filepath.Join(root, "ordinary", "status"))
	protectedViaFD := fdPath + "/../status"
	if data, err := exec.Command("cat", protectedViaFD).Output(); err != nil || string(data) != "protected" {
		t.Fatalf("child protected read %q = %q, %v", protectedViaFD, data, err)
	}
	if got := ProtectedReach(protectedViaFD, home, NewTargetMemo()); got == GradeNone {
		t.Errorf("protected fixed-PID fd path %q grade=None", protectedViaFD)
	}
}
