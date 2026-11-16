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

// The first import reads a service.json into the protected record, so it may
// only trust what no other account controls (GAP-0053 REVIEW-5 MF1). A file the
// group or other accounts can write names no port: it is not imported, the
// account gets a fresh one, and the setter writes it into a private copy.
func TestReadOpenCodeServicePortDoesNotImportAFileOtherAccountsCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o666, 0o622, 0o620, 0o602} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		port, err := ReadOpenCodeServicePortAsUser(home)
		if err != nil || port != 0 {
			t.Fatalf("mode %o: a file other accounts can write was imported: port=%d err=%v", mode, port, err)
		}
		// The record then gives the account its own port and the setter
		// replaces the shared file with a private copy.
		uid := os.Geteuid()
		plan := PlanOpenCodeServicePorts([]int{uid}, map[int]int{}, nil, true, nil, true, nil)
		if plan.Record[uid] != OpenCodeAccountPort(uint64(uid)) {
			t.Fatalf("mode %o: the account did not get its own port: %+v", mode, plan)
		}
		result, err := SetOpenCodeServicePort(home, plan.Record[uid])
		if err != nil || result.Port != plan.Record[uid] {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o: the file after the setter: %v %v", mode, info, err)
		}
	}
}

// Benign twin: the modes OpenCode and editors create for a private file are
// still imported.
func TestReadOpenCodeServicePortImportsAnOrdinaryPrivateFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
			t.Fatalf("mode %o: port=%d err=%v", mode, port, err)
		}
	}
}

// The read seals what the setter seals, before it opens anything, so nobody
// holding the folder group can rename the file between the read and the
// record. The private-group stow layout keeps importing.
func TestReadOpenCodeServicePortSealsAGroupWritableFolderBeforeReading(t *testing.T) {
	forcePrivateGroup(t)
	for _, layout := range openCodeSealLayouts() {
		t.Run(layout.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Chmod(home, 0o755); err != nil {
				t.Fatal(err)
			}
			open := resolvedFolders(t, layout.build(t, home))
			port, sealed, err := ReadOpenCodeServicePortSealed(home)
			if err != nil || port != 25001 {
				t.Fatalf("a private-group layout did not import: port=%d err=%v", port, err)
			}
			if !slices.Equal(sealed, open) {
				t.Fatalf("sealed %v, want %v", sealed, open)
			}
			for _, dir := range open {
				if info, err := os.Stat(dir); err != nil || info.Mode()&os.ModeSticky == 0 {
					t.Fatalf("%s was not made sticky: %v %v", dir, info, err)
				}
			}
			// A second read has nothing left to seal.
			if port, sealed, err := ReadOpenCodeServicePortSealed(home); err != nil || port != 25001 || len(sealed) != 0 {
				t.Fatalf("second read: %d %v %v", port, sealed, err)
			}
		})
	}
}

// A closed folder keeps its mode and nothing is sealed (benign twin).
func TestReadOpenCodeServicePortLeavesAClosedFolderAlone(t *testing.T) {
	forcePrivateGroup(t)
	for _, mode := range []os.FileMode{0o700, 0o755} {
		home := t.TempDir()
		if err := os.Chmod(home, 0o755); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(OpenCodeServiceConfigPath(home))
		sealTestMkdir(t, dir, mode)
		sealTestFile(t, dir)
		port, sealed, err := ReadOpenCodeServicePortSealed(home)
		if err != nil || port != 25001 || len(sealed) != 0 {
			t.Fatalf("mode %o: %d %v %v", mode, port, sealed, err)
		}
		if info, _ := os.Stat(dir); info.Mode() != os.ModeDir|mode {
			t.Fatalf("mode %o became %v", mode, info.Mode())
		}
	}
}

// A folder the group is not provably private to is refused before the file is
// opened, as the setter refuses it.
func TestReadOpenCodeServicePortRefusesASharedGroupFolder(t *testing.T) {
	old := openCodeOwnerPrivateGroup
	openCodeOwnerPrivateGroup = func(string, os.FileInfo) bool { return false }
	t.Cleanup(func() { openCodeOwnerPrivateGroup = old })
	home := t.TempDir()
	dir := filepath.Dir(OpenCodeServiceConfigPath(home))
	sealTestMkdir(t, dir, 0o775)
	sealTestFile(t, dir)
	if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
		t.Fatalf("a folder a shared group can write was read: port=%d err=%v", port, err)
	}
}

// asOtherAccount runs a short Python script as an unprivileged account that
// holds the test account group (supplementary), the same account the setter
// tests use. It skips where root through sudo is not available.
func asOtherAccount(t *testing.T, script string, args ...string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged account to run the reader")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("needs passwordless sudo to run as a second account")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	full := append([]string{"-n", "python3", "-I", "-c", script}, args...)
	if output, err := exec.Command("sudo", full...).CombinedOutput(); err != nil {
		t.Fatalf("the second account failed: %v: %s", err, output)
	}
}

const otherAccountPrelude = `import os, sys
gid = int(sys.argv[1])
os.setgroups([65534, gid])
os.setgid(65534)
os.setuid(65534)
`

// The attack of REVIEW-5 MF1: a second account holding the folder group
// renames the account file and creates one of its own with a port it chose.
// The read must not return that port.
func TestReadOpenCodeServicePortIgnoresAFileAGroupMemberReplaced(t *testing.T) {
	home := reachableHome(t)
	config := filepath.Join(home, ".config")
	dir := filepath.Join(config, "opencode")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "service.json")
	if err := os.WriteFile(file, []byte(`{"port":25001}`), 0o600); err != nil {
		t.Fatal(err)
	}
	asOtherAccount(t, otherAccountPrelude+`path = sys.argv[2]
os.rename(path, path + ".old")
with open(path, "w") as f:
    f.write("{\"port\":25002}")
os.chmod(path, 0o644)
`, strconv.Itoa(os.Getegid()), file)
	port, err := ReadOpenCodeServicePortAsUser(home)
	if port == 25002 {
		t.Fatalf("the port another account chose was imported (err=%v)", err)
	}
	if err == nil {
		t.Fatalf("a file of another account was read without an error: port=%d", port)
	}
}

// The same account edits a group-writable file of the victim in place.
func TestReadOpenCodeServicePortIgnoresAGroupEditedFile(t *testing.T) {
	home := reachableHome(t)
	config := filepath.Join(home, ".config")
	dir := filepath.Join(config, "opencode")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "service.json")
	if err := os.WriteFile(file, []byte(`{"port":25001}`), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o664); err != nil {
		t.Fatal(err)
	}
	asOtherAccount(t, otherAccountPrelude+`with open(sys.argv[2], "w") as f:
    f.write("{\"port\":25002}")
`, strconv.Itoa(os.Getegid()), file)
	if port, err := ReadOpenCodeServicePortAsUser(home); port == 25002 || err != nil || port != 0 {
		t.Fatalf("a file edited by another account was imported: port=%d err=%v", port, err)
	}
}

// After the read has returned, no account holding the folder group can move
// the file away (the window between the read and the record).
func TestReadOpenCodeServicePortLeavesNoFileAGroupMemberCanReplace(t *testing.T) {
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
				if _, err := ReadOpenCodeServicePortAsUser(home); err != nil {
					return
				}
				service, err := filepath.EvalSymlinks(OpenCodeServiceConfigPath(home))
				if err != nil {
					t.Fatal(err)
				}
				if otherAccountRenames(t, service, primary) {
					t.Fatalf("an account holding the folder group moved %s after the import read returned", service)
				}
				if _, err := os.Stat(service); err != nil {
					t.Fatalf("the file is gone: %v", err)
				}
			})
		}
	}
}

// chownToOtherAccount gives path to another uid (root, or sudo), and gives it
// back when the test ends so the scratch folder can be removed.
func chownToOtherAccount(t *testing.T, path string) {
	t.Helper()
	uid := strconv.Itoa(os.Geteuid())
	if os.Geteuid() == 0 {
		if err := os.Lchown(path, 65534, -1); err != nil {
			t.Skip(err)
		}
		return
	}
	if err := exec.Command("sudo", "-n", "chown", "65534", path).Run(); err != nil {
		t.Skip("needs passwordless sudo to give a file to a second account")
	}
	t.Cleanup(func() { _ = exec.Command("sudo", "-n", "chown", uid, path).Run() })
}

func TestReadOpenCodeServicePortRefusesAnEntryOfAnotherAccount(t *testing.T) {
	for _, target := range []string{"file", "opencode folder", "config folder"} {
		t.Run(target, func(t *testing.T) {
			home := t.TempDir()
			config := filepath.Join(home, ".config")
			dir := filepath.Join(config, "opencode")
			sealTestMkdir(t, config, 0o700)
			sealTestMkdir(t, dir, 0o700)
			file := filepath.Join(dir, "service.json")
			if err := os.WriteFile(file, []byte(`{"port":25002}`), 0o644); err != nil {
				t.Fatal(err)
			}
			chownToOtherAccount(t, map[string]string{"file": file, "opencode folder": dir, "config folder": config}[target])
			if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
				t.Fatalf("an entry of another account was read: port=%d err=%v", port, err)
			}
		})
	}
}
