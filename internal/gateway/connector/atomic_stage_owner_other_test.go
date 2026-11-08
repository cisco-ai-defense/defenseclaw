//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type stageChown struct {
	path     string
	uid, gid int
}

// asRootFor stands in for a root process that acts for the account running the
// test: the test cannot be root, so it records the chown a root run makes
// instead of making it.
func asRootFor(t *testing.T, trusted bool) *[]stageChown {
	t.Helper()
	var calls []stageChown
	oldEUID, oldTrusted, oldChown := atomicStageEUID, atomicStageTrusted, atomicStageChown
	atomicStageEUID = func() int { return 0 }
	atomicStageTrusted = func(uint32) bool { return trusted }
	atomicStageChown = func(path string, uid, gid int) error {
		calls = append(calls, stageChown{path, uid, gid})
		return nil
	}
	t.Cleanup(func() { atomicStageEUID, atomicStageTrusted, atomicStageChown = oldEUID, oldTrusted, oldChown })
	return &calls
}

func ownerOf(t *testing.T, path string) (int, int) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

func chownedPaths(calls []stageChown) map[string]stageChown {
	seen := map[string]stageChown{}
	for _, call := range calls {
		seen[filepath.Base(call.path)] = call
	}
	return seen
}

func TestRootRunKeepsAccountOwnerOfVendorFileWrite(t *testing.T) {
	// The test account owns the folder and the file, so a root run for it
	// must hand the staged replacement back to that account.
	if os.Geteuid() == 0 {
		t.Skip("needs an account that is not root")
	}
	uid, gid := os.Getuid(), os.Getgid()
	for name, write := range map[string]func(path string) error{
		"atomicWriteFile": func(path string) error { return atomicWriteFile(path, []byte("{\"new\":1}\n"), 0o600) },
		"atomicTransformFileWithStateDir": func(path string) error {
			return atomicTransformFileWithStateDir(path, t.TempDir(), 0o600,
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: []byte("{\"new\":1}\n")}, nil
				})
		},
	} {
		t.Run(name, func(t *testing.T) {
			calls := asRootFor(t, true)
			dir := filepath.Join(t.TempDir(), ".claude")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := write(path); err != nil {
				t.Fatal(err)
			}
			if len(*calls) == 0 {
				t.Fatal("a root run staged the vendor file without giving it to the account that owns it")
			}
			for _, call := range *calls {
				if call.uid != uid || call.gid != gid {
					t.Fatalf("staged file went to %d:%d, want the account %d:%d", call.uid, call.gid, uid, gid)
				}
			}
		})
	}
}

func TestRootRunNewVendorFileAndFoldersTakeTheAccountOwnerOfTheHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an account that is not root")
	}
	calls := asRootFor(t, true)
	home := t.TempDir()
	path := filepath.Join(home, ".copilot", "hooks", "defenseclaw.json")
	if err := atomicWriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := chownedPaths(*calls)
	for _, name := range []string{".copilot", "hooks"} {
		if got, ok := seen[name]; !ok || got.uid != os.Getuid() {
			t.Fatalf("folder %s created by a root run was not given to the account: %+v", name, *calls)
		}
	}
	staged := 0
	for _, call := range *calls {
		if filepath.Dir(call.path) == filepath.Dir(path) && filepath.Base(call.path) != "hooks" {
			staged++
		}
	}
	if staged != 1 {
		t.Fatalf("the staged new file was not given to the account exactly once: %+v", *calls)
	}
}

func TestVendorFileWriteKeepsItsOwnerWhereNoAccountOwnsIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an account that is not root")
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	for name, tc := range map[string]struct {
		euid    int
		trusted bool
	}{
		"not root":                    {euid: os.Geteuid(), trusted: true},
		"owner is not a trusted user": {euid: 0, trusted: false},
	} {
		t.Run(name, func(t *testing.T) {
			calls := asRootFor(t, tc.trusted)
			atomicStageEUID = func() int { return tc.euid }
			if err := atomicWriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if len(*calls) != 0 {
				t.Fatalf("ownership changed where it must stay as written: %+v", *calls)
			}
			if uid, _ := ownerOf(t, path); uid != os.Getuid() {
				t.Fatalf("file owner %d", uid)
			}
		})
	}
}

type fakeStatInfo struct{ stat syscall.Stat_t }

func (fakeStatInfo) Name() string       { return "x" }
func (fakeStatInfo) Size() int64        { return 0 }
func (fakeStatInfo) Mode() fs.FileMode  { return 0o755 }
func (fakeStatInfo) ModTime() time.Time { return time.Time{} }
func (fakeStatInfo) IsDir() bool        { return true }
func (f fakeStatInfo) Sys() any         { return &f.stat }

func TestRootOwnedFolderKeepsRootAsOwnerOfWhatRootWrites(t *testing.T) {
	asRootFor(t, true)
	if _, _, ok := atomicStageTrustedOwner(fakeStatInfo{stat: syscall.Stat_t{Uid: 0}}); ok {
		t.Fatal("a root-owned folder was treated as an account to give files to")
	}
	if uid, _, ok := atomicStageTrustedOwner(fakeStatInfo{stat: syscall.Stat_t{Uid: 501, Gid: 20}}); !ok || uid != 501 {
		t.Fatal("an account-owned folder was not recognised")
	}
}
