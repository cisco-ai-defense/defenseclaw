// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type cleanMirrorFixture struct {
	root string
	uid  string
	key  SessionKey
	now  time.Time
}

func newCleanMirrorFixture(t *testing.T) *cleanMirrorFixture {
	t.Helper()
	top := t.TempDir()
	previous := foreignHookCleanMirrorTrustTop
	foreignHookCleanMirrorTrustTop = top
	t.Cleanup(func() { foreignHookCleanMirrorTrustTop = previous })
	data := filepath.Join(top, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	root := managed.ForeignHookCleanDir(data)
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	return &cleanMirrorFixture{
		root: root,
		uid:  strconv.Itoa(os.Getuid()),
		key:  SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:boot:1234:5678"},
		now:  time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC),
	}
}

func (f *cleanMirrorFixture) write(t *testing.T) {
	t.Helper()
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, f.key, ForeignHookStateHash(nil), f.now); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func (f *cleanMirrorFixture) check(key SessionKey, at time.Time) error {
	return CheckForeignHookCleanMirror(ForeignHookCleanMirrorCheck{Root: f.root, ServiceUID: os.Getuid(), CallerUID: os.Getuid(), Key: key, Now: at})
}

func (f *cleanMirrorFixture) entry() string {
	return foreignHookCleanMirrorPath(f.root, f.uid, f.key.Connector, sessionKindProcess, f.key.Process)
}

func TestForeignHookCleanMirrorWrittenIsTrusted(t *testing.T) {
	f := newCleanMirrorFixture(t)
	f.write(t)
	if err := f.check(f.key, f.now.Add(time.Hour)); err != nil {
		t.Fatalf("a fresh entry must pass: %v", err)
	}
	for _, path := range []string{filepath.Join(f.root, f.uid), f.entry()} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644)
		if info.IsDir() {
			want = 0o711
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, want %v", path, info.Mode().Perm(), want)
		}
	}
	if _, err := os.Lstat(foreignHookCleanMirrorPath(f.root, f.uid, f.key.Connector, sessionKindSession, f.key.Session)); err != nil {
		t.Fatalf("the session key entry is written too: %v", err)
	}
}

func TestForeignHookCleanMirrorRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time)
	}{
		{"missing", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			return f.key, f.now
		}},
		{"expired", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			return f.key, f.now.Add(ForeignHookCleanMirrorTTL)
		}},
		{"written in the future", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			return f.key, f.now.Add(-2 * foreignHookCleanMirrorSkew)
		}},
		{"another agent process", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			key := f.key
			key.Process = "linux:boot:1234:9999"
			return key, f.now
		}},
		{"another connector", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			key := f.key
			key.Connector = "opencode"
			return key, f.now
		}},
		{"a session with no entry of its own", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			// A clean agent process that resumes another session.
			f.write(t)
			key := f.key
			key.Session = "s-blocked"
			return key, f.now
		}},
		{"process entry without its session entry", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := os.Remove(foreignHookCleanMirrorPath(f.root, f.uid, f.key.Connector, sessionKindSession, f.key.Session)); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"session key only", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			key := f.key
			key.Process = ""
			return key, f.now
		}},
		{"dropped after a denial", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := DropForeignHookCleanMirrors(f.root, f.uid, f.key); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"dropped by a guardian removal", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := DropForeignHookCleanMirrorsForAccount(f.root, f.uid); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"dropped by a guardian removal of an account named by SID", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := DropForeignHookCleanMirrorsForAccount(f.root, "S-1-5-21-1-2-3-1001"); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"entry writable by others", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := os.Chmod(f.entry(), 0o666); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"account folder writable by others", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := os.Chmod(filepath.Join(f.root, f.uid), 0o777); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"root writable by others", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := os.Chmod(f.root, 0o777); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"symbolic link entry", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			copyPath := filepath.Join(filepath.Dir(f.root), "copy.json")
			data, err := os.ReadFile(f.entry())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(copyPath, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(f.entry()); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(copyPath, f.entry()); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"symbolic link account folder", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			moved := filepath.Join(filepath.Dir(f.root), "moved")
			if err := os.Rename(filepath.Join(f.root, f.uid), moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, filepath.Join(f.root, f.uid)); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"hard link entry", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			if err := os.Link(f.entry(), filepath.Join(filepath.Dir(f.root), "link.json")); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"unknown field", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			data, err := os.ReadFile(f.entry())
			if err != nil {
				t.Fatal(err)
			}
			patched := strings.Replace(string(data), `{"v":1,`, `{"v":1,"blocked":false,`, 1)
			if err := os.WriteFile(f.entry(), []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"trailing data", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			data, err := os.ReadFile(f.entry())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.entry(), append(data, []byte(`{}`)...), 0o644); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now
		}},
		{"lifetime beyond the TTL", func(t *testing.T, f *cleanMirrorFixture) (SessionKey, time.Time) {
			f.write(t)
			data, err := os.ReadFile(f.entry())
			if err != nil {
				t.Fatal(err)
			}
			expires := f.now.Add(ForeignHookCleanMirrorTTL).UTC().Format(time.RFC3339Nano)
			later := f.now.Add(10 * ForeignHookCleanMirrorTTL).UTC().Format(time.RFC3339Nano)
			if err := os.WriteFile(f.entry(), []byte(strings.Replace(string(data), expires, later, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			return f.key, f.now.Add(2 * ForeignHookCleanMirrorTTL)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCleanMirrorFixture(t)
			key, at := tc.setup(t, f)
			if err := f.check(key, at); err == nil {
				t.Fatal("the entry must be refused")
			}
		})
	}
}

// An entry the caller owns (a user-made file) is refused: only root and the
// service account are trusted.
func TestForeignHookCleanMirrorRefusesAnUntrustedOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always a trusted owner")
	}
	f := newCleanMirrorFixture(t)
	f.write(t)
	err := CheckForeignHookCleanMirror(ForeignHookCleanMirrorCheck{Root: f.root, ServiceUID: os.Getuid() + 1, CallerUID: os.Getuid(), Key: f.key, Now: f.now})
	if err == nil {
		t.Fatal("an entry owned by the caller must be refused")
	}
}

// Every ancestor of the root up to / must be owned by root and not writable
// by other accounts.
func TestForeignHookCleanMirrorRefusesAnUntrustedAncestor(t *testing.T) {
	top := t.TempDir()
	previous := foreignHookCleanMirrorTrustTop
	foreignHookCleanMirrorTrustTop = top
	t.Cleanup(func() { foreignHookCleanMirrorTrustTop = previous })
	mid := filepath.Join(top, "mid")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	root := managed.ForeignHookCleanDir(filepath.Join(mid, "data"))
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:boot:1:2"}
	now := time.Now()
	if err := WriteForeignHookCleanMirrors(root, strconv.Itoa(os.Getuid()), key, "", now); err != nil {
		t.Fatal(err)
	}
	if err := CheckForeignHookCleanMirror(ForeignHookCleanMirrorCheck{Root: root, ServiceUID: os.Getuid(), CallerUID: os.Getuid(), Key: key, Now: now}); err == nil {
		t.Fatal("a world-writable ancestor must be refused")
	}
}

// An allow within the refresh window keeps the entry; past it the entry is
// written again with a new lifetime. A full account folder takes no new
// entry after its expired ones are pruned.
func TestForeignHookCleanMirrorRefreshAndLimit(t *testing.T) {
	f := newCleanMirrorFixture(t)
	f.write(t)
	first, err := os.ReadFile(f.entry())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, f.key, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(f.entry()); string(again) != string(first) {
		t.Fatal("an entry written moments ago is kept")
	}
	stale := time.Now().Add(-2 * foreignHookCleanMirrorRefresh)
	if err := os.Chtimes(f.entry(), stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, f.key, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	f.now = time.Now()
	if err := f.check(f.key, f.now); err != nil {
		t.Fatalf("a rewritten entry must pass: %v", err)
	}
	if again, _ := os.ReadFile(f.entry()); string(again) == string(first) {
		t.Fatal("an entry written before the refresh window must be written again")
	}
	dir := filepath.Join(f.root, f.uid)
	old := time.Now().Add(-2 * ForeignHookCleanMirrorTTL)
	for i := 0; i < foreignHookCleanMirrorDirLimit; i++ {
		path := filepath.Join(dir, "p-filler-"+strconv.Itoa(i)+".json")
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	other := f.key
	other.Process, other.Session = "linux:boot:9:9", "s-9"
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, other, "", time.Now()); err != nil {
		t.Fatalf("pruning the expired entries must make room: %v", err)
	}
	for i := 0; i < foreignHookCleanMirrorDirLimit; i++ {
		_ = os.WriteFile(filepath.Join(dir, "p-fresh-"+strconv.Itoa(i)+".json"), []byte("{}"), 0o644)
	}
	third := f.key
	third.Process, third.Session = "linux:boot:8:8", "s-8"
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, third, "", time.Now()); err == nil {
		t.Fatal("a full account folder must take no new entry")
	}
}

// Another account's caller uid finds no entry of its own.
func TestForeignHookCleanMirrorRefusesAnotherAccount(t *testing.T) {
	f := newCleanMirrorFixture(t)
	f.write(t)
	err := CheckForeignHookCleanMirror(ForeignHookCleanMirrorCheck{Root: f.root, ServiceUID: os.Getuid(), CallerUID: os.Getuid() + 1, Key: f.key, Now: f.now})
	if err == nil {
		t.Fatal("another account must not read this account's entry")
	}
}

func TestForeignHookCleanMirrorWriteNeedsTheRootAndAUID(t *testing.T) {
	f := newCleanMirrorFixture(t)
	if err := WriteForeignHookCleanMirrors(filepath.Join(f.root, "absent"), f.uid, f.key, "", f.now); err == nil {
		t.Fatal("a missing root must not be created")
	}
	if err := WriteForeignHookCleanMirrors(f.root, "S-1-5-21-1-2-3-1001", f.key, "", f.now); err == nil {
		t.Fatal("an identity that is not a uid gets no entry")
	}
	if err := os.Chmod(f.root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := WriteForeignHookCleanMirrors(f.root, f.uid, f.key, "", f.now); err == nil {
		t.Fatal("a root writable by others must be refused")
	}
	if err := DropForeignHookCleanMirrorsForAccount(filepath.Join(f.root, "absent"), f.uid); err != nil {
		t.Fatalf("a missing root has nothing to drop: %v", err)
	}
}
