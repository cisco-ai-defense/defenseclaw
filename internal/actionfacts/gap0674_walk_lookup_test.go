package actionfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestGAP0674WalkSkipsFilesOfAFolderItCannotEnter is RV-T6C P4-1
// (substrate-1:GAP-0674): a folder that can be listed but not entered (mode
// 0644: read, no search) names its files, but neither the walk nor the
// agent's grep can open one, so the resolve records no read of them. The walk
// that took the folder read's word for every file it named recorded one. A
// folder that can be entered still costs one lookup, not one per file.
func TestGAP0674WalkSkipsFilesOfAFolderItCannotEnter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows checks no search permission apart from read (credentialWalkSearchChecked)")
	}
	root := t.TempDir()
	write := func(rel string) string {
		file := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	open := []string{write("open/.env"), write("open/.npmrc"), write("open/deeper/.env")}
	lockedFile := write("locked/.env")
	locked := filepath.Dir(lockedFile)
	if err := os.Chmod(locked, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := os.Stat(lockedFile); err == nil {
		t.Skip("this user enters a folder of mode 0644 (root, or a filesystem without permissions)")
	}
	walk := credentialPathWalk(credentialWalkBudgetUnbounded(), root, root, credentialWalkFilter{}, credentialPathWalkBounds, credentialWalkRoomAll())
	if slices.Contains(walk.found, lockedFile) {
		t.Errorf("the walk found %s, a file of a folder no one can enter: %v", lockedFile, walk.found)
	}
	got := slices.Clone(walk.found)
	slices.Sort(got)
	slices.Sort(open)
	if !slices.Equal(got, open) {
		t.Errorf("walk found %v, want %v", got, open)
	}
	facts := Analyze(Input{Tool: "exec", Command: "grep -r KEY " + root, CWD: root, ActiveHome: t.TempDir()})
	for _, read := range facts.CredentialPathReads() {
		if strings.HasPrefix(read.Value, locked) {
			t.Errorf("the resolve records a read of the folder no one can enter: %+v", read)
		}
	}
}

// TestGAP0674WalkLooksUpAPathWindowsMayNotName: on Windows, a file the folder
// read names under a path longer than credentialWalkWindowsPathBytes is
// looked up before it counts (a path past 32,767 UTF-16 units cannot be
// opened, so the agent's grep cannot read it); a shorter one is not, and
// other systems look up none for its length.
func TestGAP0674WalkLooksUpAPathWindowsMayNotName(t *testing.T) {
	long := `C:\` + strings.Repeat(`d\`, credentialWalkWindowsPathBytes/2) + `.env`
	if got, want := credentialWalkPathTooLong(long), runtime.GOOS == "windows"; got != want {
		t.Errorf("credentialWalkPathTooLong(%d bytes) = %v, want %v on %s", len(long), got, want, runtime.GOOS)
	}
	if credentialWalkPathTooLong(long[:credentialWalkWindowsPathBytes]) {
		t.Errorf("a path of %d bytes is looked up for its length", credentialWalkWindowsPathBytes)
	}
	if credentialWalkWindowsPathBytes >= 32_767-len(`\\?\`)-1 {
		t.Errorf("credentialWalkWindowsPathBytes %d leaves no room for the \\\\?\\ prefix and the NUL", credentialWalkWindowsPathBytes)
	}
}
