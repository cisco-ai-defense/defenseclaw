//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// openCodeSealLayout builds one service.json layout under home and returns the
// folders it opens to the group (mode 0775), outermost first.
type openCodeSealLayout struct {
	name string
	// linked: ~/.config/opencode is a link (the stow layout). A matching port is
	// a no-op there; a differing one is refused, as the writer never writes
	// through a link in place of the folder.
	linked bool
	build  func(t *testing.T, home string) []string
}

func sealTestMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

func sealTestFile(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"port":25001}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resolvedFolders spells the folders the way the walk reports them, with every
// link resolved (a macOS temporary folder is /private/var behind /var).
func resolvedFolders(t *testing.T, folders []string) []string {
	t.Helper()
	resolved := make([]string, len(folders))
	for i, folder := range folders {
		real, err := filepath.EvalSymlinks(folder)
		if err != nil {
			t.Fatal(err)
		}
		resolved[i] = real
	}
	return resolved
}

func openCodeSealLayouts() []openCodeSealLayout {
	return []openCodeSealLayout{
		{"opencode folder open to the group", false, func(t *testing.T, home string) []string {
			config, dir := filepath.Join(home, ".config"), filepath.Dir(OpenCodeServiceConfigPath(home))
			sealTestMkdir(t, config, 0o755)
			sealTestMkdir(t, dir, 0o775)
			sealTestFile(t, dir)
			return []string{dir}
		}},
		{"config and opencode folders open to the group", false, func(t *testing.T, home string) []string {
			config, dir := filepath.Join(home, ".config"), filepath.Dir(OpenCodeServiceConfigPath(home))
			sealTestMkdir(t, config, 0o775)
			sealTestMkdir(t, dir, 0o775)
			sealTestFile(t, dir)
			return []string{config, dir}
		}},
		{"stow link into dotfiles open to the group", true, func(t *testing.T, home string) []string {
			config := filepath.Join(home, ".config")
			dotfiles := filepath.Join(home, "dotfiles")
			target := filepath.Join(dotfiles, "opencode")
			sealTestMkdir(t, config, 0o755)
			sealTestMkdir(t, dotfiles, 0o755)
			sealTestMkdir(t, target, 0o775)
			sealTestFile(t, target)
			if err := os.Symlink(target, filepath.Join(config, "opencode")); err != nil {
				t.Skip(err)
			}
			return []string{target}
		}},
	}
}

// forcePrivateGroup makes the private-group proof answer yes, so the layout is
// judged by what the setter does about the group-write bit and not by the
// groups of the machine running the test.
func forcePrivateGroup(t *testing.T) {
	t.Helper()
	old := openCodeOwnerPrivateGroup
	openCodeOwnerPrivateGroup = func(string, os.FileInfo) bool { return true }
	t.Cleanup(func() { openCodeOwnerPrivateGroup = old })
}

// A folder the account's group can write is not accepted on the strength of a
// group record (REVIEW-4 MF1): an account that holds the group as its primary
// or a supplementary group, through a directory service or granted outside
// every database, still reaches the folder. The setter makes the folder sticky
// as its owner, so the entries in it can only be renamed by their owners, and
// says so. A matching port and a differing port are treated alike.
func TestSetOpenCodeServicePortSealsAGroupWritableFolderItAccepts(t *testing.T) {
	forcePrivateGroup(t)
	for _, layout := range openCodeSealLayouts() {
		for _, port := range []int{25001, 25002} {
			t.Run(layout.name+"/"+strconv.Itoa(port), func(t *testing.T) {
				home := t.TempDir()
				if err := os.Chmod(home, 0o755); err != nil {
					t.Fatal(err)
				}
				open := resolvedFolders(t, layout.build(t, home))
				result, err := SetOpenCodeServicePort(home, port)
				if layout.linked && port != 25001 {
					if err == nil {
						t.Fatalf("a differing port was written through a link: %+v", result)
					}
				} else if err != nil {
					t.Fatalf("a folder owned by the account in its private group was refused: %v", err)
				} else if result.Changed != (port != 25001) {
					t.Fatalf("changed=%v for port %d: %+v", result.Changed, port, result)
				}
				if !slices.Equal(result.Sealed, open) {
					t.Fatalf("sealed %v, want %v", result.Sealed, open)
				}
				for _, dir := range open {
					info, err := os.Stat(dir)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode()&os.ModeSticky == 0 || info.Mode().Perm() != 0o775 {
						t.Fatalf("%s: mode %v, want 0775 and sticky", dir, info.Mode())
					}
				}
				// A second pass has nothing left to seal and changes nothing more.
				again, err := SetOpenCodeServicePort(home, port)
				if (err != nil) != (layout.linked && port != 25001) || again.Changed || len(again.Sealed) != 0 {
					t.Fatalf("second pass: %+v %v", again, err)
				}
			})
		}
	}
}

// Benign twin: folders that no other account can write (0700, 0755) keep their
// modes; nothing is sealed and a matching port stays a no-op.
func TestSetOpenCodeServicePortLeavesAClosedFolderModeAlone(t *testing.T) {
	forcePrivateGroup(t)
	for _, mode := range []os.FileMode{0o700, 0o755} {
		home := t.TempDir()
		if err := os.Chmod(home, 0o755); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(OpenCodeServiceConfigPath(home))
		sealTestMkdir(t, dir, mode)
		sealTestFile(t, dir)
		result, err := SetOpenCodeServicePort(home, 25001)
		if err != nil || result.Changed || len(result.Sealed) != 0 {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
		if info, _ := os.Stat(dir); info.Mode() != os.ModeDir|mode {
			t.Fatalf("mode %o became %v", mode, info.Mode())
		}
	}
}

// A folder reached through a link is not sealed: the setter refuses it instead
// of changing what the link leads to.
func TestOpenCodeSealSharedFolderRefusesALink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	sealTestMkdir(t, real, 0o775)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if sealed, err := openCodeSealSharedFolder(link, info); err == nil || sealed {
		t.Fatalf("a link was sealed: %v %v", sealed, err)
	}
	if got, _ := os.Stat(real); got.Mode()&os.ModeSticky != 0 {
		t.Fatalf("the link target was changed: %v", got.Mode())
	}
}

// macOS reports a link as mode 0755 where Linux reports 0777, so the refusal
// of a link must not depend on the group-write bit the platform shows for it.
type macLinkInfo struct{ os.FileInfo }

func (macLinkInfo) Mode() os.FileMode { return os.ModeSymlink | 0o755 }

func TestOpenCodeSealSharedFolderRefusesALinkWhateverModeTheSystemReportsForIt(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	sealTestMkdir(t, real, 0o775)
	info, err := os.Lstat(real)
	if err != nil {
		t.Fatal(err)
	}
	if sealed, err := openCodeSealSharedFolder(real, macLinkInfo{info}); err == nil || sealed {
		t.Fatalf("a link reported as 0755 was sealed: %v %v", sealed, err)
	}
	// Benign twin: the same folder, reported as the folder it is, is sealed.
	if sealed, err := openCodeSealSharedFolder(real, info); err != nil || !sealed {
		t.Fatalf("a group-writable folder was not sealed: %v %v", sealed, err)
	}
}

// otherAccountRenames runs, as an unprivileged account that holds gid either as
// a supplementary or as its primary group, the one operation that matters: it
// renames path. It reports whether the rename succeeded. Skips where root
// through sudo is not available without a password.
func otherAccountRenames(t *testing.T, path string, primary bool) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged account to run the setter")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("needs passwordless sudo to run as a second account")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	const script = `import os, sys
path, gid, primary = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
os.setgroups([] if primary else [65534, gid])
os.setgid(gid if primary else 65534)
os.setuid(65534)
os.rename(path, path + ".moved")
`
	flag := "0"
	if primary {
		flag = "1"
	}
	return exec.Command("sudo", "-n", "python3", "-I", "-c", script, path, strconv.Itoa(os.Getegid()), flag).Run() == nil
}

// The class, end to end (REVIEW-4 MF1): whatever the group databases say, once
// the setter has returned without an error no second account that holds the
// folder's group can move service.json away. Either the setter refuses, or the
// rename fails.
func TestSetOpenCodeServicePortLeavesNoFileAGroupMemberCanReplace(t *testing.T) {
	forcePrivateGroup(t)
	for _, layout := range openCodeSealLayouts() {
		for _, primary := range []bool{false, true} {
			name := layout.name + "/supplementary group"
			if primary {
				name = layout.name + "/primary group"
			}
			t.Run(name, func(t *testing.T) {
				home := reachableHome(t)
				layout.build(t, home)
				if _, err := SetOpenCodeServicePort(home, 25001); err != nil {
					return
				}
				// The file is reached through the real path, links followed.
				service, err := filepath.EvalSymlinks(OpenCodeServiceConfigPath(home))
				if err != nil {
					t.Fatal(err)
				}
				if otherAccountRenames(t, service, primary) {
					t.Fatalf("an account holding the folder's group moved %s after the setter reported the port as reconciled", service)
				}
				if _, err := os.Stat(service); err != nil {
					t.Fatalf("the file is gone: %v", err)
				}
			})
		}
	}
}
