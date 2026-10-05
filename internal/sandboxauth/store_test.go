// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T, opts ...StoreOption) (*FileStore, string) {
	t.Helper()
	path := DefaultStorePath(t.TempDir())
	return openStore(t, path, opts...), path
}

// openStore opens a table the way another gateway process would.
func openStore(t *testing.T, path string, opts ...StoreOption) *FileStore {
	t.Helper()
	s, err := OpenFileStore(path, opts...)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	return s
}

// mint mints a binding for a codex sandbox with the given name.
func mint(t *testing.T, s *FileStore, name string) (Binding, string) {
	t.Helper()
	b, token, err := s.Mint(mountSpec(name, "codex"))
	if err != nil {
		t.Fatalf("Mint(%s): %v", name, err)
	}
	return b, token
}

// refused checks that a store no longer honours a credential.
func refused(t *testing.T, s *FileStore, token, why string) {
	t.Helper()
	if _, err := s.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("%s: Match = %v, want ErrUnauthenticated", why, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func TestMintMatchAndPersistence(t *testing.T) {
	s, path := newStore(t)
	b, token := mint(t, s, "dc-app")
	if !LooksLikeToken(token) || b.TokenHash != HashToken(token) || b.Generation != 1 || b.ID == "" {
		t.Fatalf("minted %q, binding = %+v", token, b)
	}
	if got, err := s.Match(token); err != nil || got.ID != b.ID {
		t.Fatalf("Match = %+v, %v", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), strings.TrimPrefix(token, TokenPrefix)) ||
		!strings.Contains(string(data), b.TokenHash) {
		t.Fatal("the binding table must hold the credential hash, never the credential")
	}
	assertMode(t, path, 0o600)
	assertMode(t, filepath.Dir(path), 0o700)
	if got, err := openStore(t, path).Match(token); err != nil || got.ID != b.ID {
		t.Fatalf("reopened Match = %+v, %v", got, err)
	}
	for _, presented := range []string{
		"", "Bearer " + token, token + "x", strings.ToUpper(token), TokenPrefix + strings.Repeat("A", 43),
		"openshell:resolve:env:v1_DEFENSECLAW_SANDBOX_TOKEN", strings.Repeat("a", 64),
	} {
		refused(t, s, presented, fmt.Sprintf("presented %q", presented))
	}
}

func TestMintRefusesDuplicateSandbox(t *testing.T) {
	s, _ := newStore(t)
	spec := mountSpec("dc-app", "codex")
	spec.SandboxID = "sbx-1"
	if _, _, err := s.Mint(spec); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Mint(spec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	other := mountSpec("dc-other", "codex")
	other.SandboxID = "sbx-1"
	if _, _, err := s.Mint(other); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate sandbox id: %v", err)
	}
	if _, _, err := s.Mint(Spec{SandboxName: "x"}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("invalid spec: %v", err)
	}
}

func TestRotateRevokeAndExpiry(t *testing.T) {
	clock := newTestClock()
	s, _ := newStore(t, WithClock(clock.Now))
	spec := mountSpec("dc-app", "codex")
	spec.TTL = time.Hour
	b, oldToken, err := s.Mint(spec)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * time.Minute)
	rotated, newToken, err := s.Rotate(b.ID)
	if err != nil || newToken == oldToken || rotated.Generation != 2 || rotated.TokenHash == b.TokenHash {
		t.Fatalf("rotation did not replace the credential: %+v, %v", rotated, err)
	}
	if !rotated.ExpiresAt.Equal(clock.Now().Add(time.Hour)) {
		t.Fatalf("rotation must restart the ttl window, expires %v", rotated.ExpiresAt)
	}
	refused(t, s, oldToken, "old credential after rotate")
	if got, err := s.Match(newToken); err != nil || got.Generation != 2 {
		t.Fatalf("new credential: %+v %v", got, err)
	}
	if _, _, err := s.Rotate("sb_ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate unknown: %v", err)
	}
	clock.Advance(time.Hour)
	refused(t, s, newToken, "expired credential")

	revoked, token := mint(t, s, "dc-revoked")
	if err := s.Revoke(revoked.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	refused(t, s, token, "revoked credential")
	if err := s.Revoke(revoked.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := s.Get(revoked.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get revoked: %v", err)
	}
	mint(t, s, "dc-revoked") // the name is free again once revoked
}

func TestUpdate(t *testing.T) {
	s, _ := newStore(t)
	b, token := mint(t, s, "dc-app")
	updated, err := s.Update(b.ID, func(spec *Spec) error {
		spec.SandboxID = "0f5c7a3e-1111-2222-3333-444455556666"
		spec.HookContractID = "codex-hooks-v4"
		return nil
	})
	if err != nil || updated.SandboxID == "" || updated.TokenHash != b.TokenHash || updated.Generation != b.Generation {
		t.Fatalf("Update = %+v, %v", updated, err)
	}
	if got, err := s.Match(token); err != nil || got.HookContractID != "codex-hooks-v4" {
		t.Fatalf("Match after update = %+v, %v", got, err)
	}
	// Non-authority fields stay editable, and restating the same routes or
	// workdir in another order is not a change.
	updated, err = s.Update(b.ID, func(spec *Spec) error {
		spec.AgentVersion = "0.130.0"
		spec.PolicyProfile = "strict"
		spec.RateLimit = RateLimit{RequestsPerSecond: 5}
		spec.TTL = time.Hour
		spec.Routes = []Route{RouteOTLP, RouteNotify, RouteHook, RouteHook}
		spec.Workdir.Masks = append(spec.Workdir.Masks, spec.Workdir.Masks...)
		return nil
	})
	if err != nil || updated.AgentVersion != "0.130.0" || updated.PolicyProfile != "strict" ||
		updated.TTLSeconds != 3600 || updated.ExpiresAt.IsZero() {
		t.Fatalf("Update of non-authority fields = %+v, %v", updated, err)
	}
	// What a live credential may call or read needs a new binding.
	for name, mutate := range map[string]func(*Spec){
		"connector":       func(spec *Spec) { spec.Connector = "claudecode" },
		"name":            func(spec *Spec) { spec.SandboxName = "dc-renamed" },
		"invalid":         func(spec *Spec) { spec.Workdir.Mode = "bogus" },
		"add route":       func(spec *Spec) { spec.Routes = append(spec.Routes, RouteInspect) },
		"drop route":      func(spec *Spec) { spec.Routes = []Route{RouteHook} },
		"mode":            func(spec *Spec) { spec.Workdir = Workdir{Mode: WorkdirCopy} },
		"mount host path": func(spec *Spec) { spec.Workdir.Mounts[0].HostPath = "/home/dev" },
		"add mount": func(spec *Spec) {
			spec.Workdir.Mounts = append(spec.Workdir.Mounts, Mount{SandboxPath: "/work/other", HostPath: "/home/dev/other"})
		},
		"read-only flag": func(spec *Spec) { spec.Workdir.Mounts[0].ReadOnly = true },
		"drop mask":      func(spec *Spec) { spec.Workdir.Masks = nil },
		"add mask":       func(spec *Spec) { spec.Workdir.Masks = append(spec.Workdir.Masks, "/work/app/secrets.json") },
	} {
		if _, err := s.Update(b.ID, func(spec *Spec) error { mutate(spec); return nil }); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("update %s: %v", name, err)
		}
	}
	if got, err := s.Get(b.ID); err != nil || len(got.Routes) != 3 || len(got.Workdir.Mounts) != 1 ||
		got.Workdir.Mounts[0].HostPath != "/home/dev/code/app" || len(got.Workdir.Masks) != 1 {
		t.Fatalf("refused updates changed the binding: %+v, %v", got, err)
	}
	callbackErr := errors.New("stop")
	if _, err := s.Update(b.ID, func(*Spec) error { return callbackErr }); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error: %v", err)
	}
	if _, err := s.Update("sb_ffffffffffffffffffffffffffffffff", func(*Spec) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update unknown: %v", err)
	}
}

func TestListLookupGet(t *testing.T) {
	s, _ := newStore(t)
	for _, name := range []string{"dc-b", "dc-a", "dc-c"} {
		mint(t, s, name)
	}
	list := s.List()
	if len(list) != 3 || list[0].SandboxName != "dc-a" || list[2].SandboxName != "dc-c" {
		t.Fatalf("List = %+v", list)
	}
	got, err := s.Lookup("dc-b")
	if err != nil || got.SandboxName != "dc-b" {
		t.Fatalf("Lookup = %+v %v", got, err)
	}
	if byID, err := s.Get(got.ID); err != nil || byID.SandboxName != "dc-b" {
		t.Fatalf("Get = %+v %v", byID, err)
	}
	if _, err := s.Lookup("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup missing: %v", err)
	}
	list[0].Workdir.Mounts[0].HostPath = "/mutated"
	if again, _ := s.Lookup("dc-a"); again.Workdir.Mounts[0].HostPath == "/mutated" {
		t.Fatal("List must return copies")
	}
}

func TestCrossProcessVisibility(t *testing.T) {
	a, path := newStore(t, WithRefreshInterval(0))
	b := openStore(t, path, WithRefreshInterval(0))
	binding, token := mint(t, a, "dc-app")
	if got, err := b.Match(token); err != nil || got.ID != binding.ID {
		t.Fatalf("second store did not see mint: %+v %v", got, err)
	}
	if err := b.Revoke(binding.ID); err != nil {
		t.Fatal(err)
	}
	refused(t, a, token, "first store after a revoke by the second")
}

func TestRefreshIntervalBoundsDiskChecks(t *testing.T) {
	clock := newTestClock()
	a, path := newStore(t, WithClock(clock.Now), WithRefreshInterval(time.Second))
	_, token := mint(t, openStore(t, path), "dc-app")
	refused(t, a, token, "store refreshed before its interval")
	clock.Advance(time.Second)
	if _, err := a.Match(token); err != nil {
		t.Fatalf("store did not refresh after its interval: %v", err)
	}
}

func TestConcurrentWritersAcrossStores(t *testing.T) {
	a, path := newStore(t)
	b := openStore(t, path)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		store := a
		if i%2 == 1 {
			store = b
		}
		wg.Add(1)
		go func(i int, store *FileStore) {
			defer wg.Done()
			_, _, err := store.Mint(mountSpec(fmt.Sprintf("dc-%02d", i), "codex"))
			errs <- err
		}(i, store)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent mint: %v", err)
		}
	}
	if n := len(openStore(t, path).List()); n != 40 {
		t.Fatalf("lost updates: %d bindings, want 40", n)
	}
}

// TestRefreshRereadsATableReplacedDuringTheRead covers a revoke published by
// another process while a refresh is reading the previous table. The
// refresh must not record the new file's identity next to the old contents:
// that pairing would pass every later identity check and keep the revoked
// credential authenticating until some unrelated mutation.
func TestRefreshRereadsATableReplacedDuringTheRead(t *testing.T) {
	a, path := newStore(t, WithRefreshInterval(0))
	b := openStore(t, path, WithRefreshInterval(0))
	revoked, token := mint(t, a, "dc-app")
	mint(t, b, "dc-other") // makes a's next Match re-read the table
	var once sync.Once
	a.afterRead = func() {
		once.Do(func() {
			if err := b.Revoke(revoked.ID); err != nil {
				t.Errorf("Revoke during refresh: %v", err)
			}
		})
	}
	refused(t, a, token, "Match during a concurrent revoke")
	a.afterRead = nil
	for i := 0; i < 3; i++ {
		refused(t, a, token, fmt.Sprintf("revoked credential on check %d", i))
	}
	a.mu.RLock()
	loaded := a.loaded
	a.mu.RUnlock()
	onDisk, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !sameFileVersion(loaded, onDisk) {
		t.Fatal("recorded table identity does not match the table on disk")
	}
}

// TestRefreshNeverOverwritesANewerMutation covers a Revoke in this process
// that lands after a refresh has read the table but before it installs it.
// The revoke must win at once, as its documentation promises.
func TestRefreshNeverOverwritesANewerMutation(t *testing.T) {
	clock := newTestClock()
	a, path := newStore(t, WithClock(clock.Now), WithRefreshInterval(time.Second))
	revoked, token := mint(t, a, "dc-app")
	mint(t, openStore(t, path), "dc-other")
	clock.Advance(time.Second)
	var once sync.Once
	a.beforeRefreshInstall = func() {
		once.Do(func() {
			if err := a.Revoke(revoked.ID); err != nil {
				t.Errorf("Revoke during refresh: %v", err)
			}
		})
	}
	refused(t, a, token, "refresh reinstalled the pre-revoke table")
	a.beforeRefreshInstall = nil
	// No refresh is due, so this is served from memory.
	refused(t, a, token, "revoked credential from memory")
	if len(a.List()) != 1 {
		t.Fatalf("in-memory table = %+v, want only the other binding", a.List())
	}
}

func TestReadStateGivesUpOnATableThatNeverSettles(t *testing.T) {
	s, _ := newStore(t)
	mint(t, s, "dc-app")
	// Every read is followed by a write, as if another process rewrote the
	// table continuously. The hook skips the nested read Mint itself does.
	n, inHook := 0, false
	s.afterRead = func() {
		if inHook {
			return
		}
		inHook = true
		defer func() { inHook = false }()
		n++
		if _, _, err := s.Mint(mountSpec(fmt.Sprintf("dc-churn-%d", n), "codex")); err != nil {
			t.Errorf("Mint: %v", err)
		}
	}
	if _, _, err := s.readState(); err == nil || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("readState on a constantly replaced table = %v", err)
	}
	if n != maxStableReadAttempts {
		t.Fatalf("readState made %d attempts, want %d", n, maxStableReadAttempts)
	}
}

func TestTamperedTableFailsClosed(t *testing.T) {
	s, path := newStore(t, WithRefreshInterval(0))
	_, token := mint(t, s, "dc-app")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	refused(t, s, token, "world-readable table")
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("OpenFileStore accepted a world-readable table")
	}
	if _, _, err := s.Mint(mountSpec("dc-other", "codex")); err == nil {
		t.Fatal("Mint overwrote a tampered table")
	}
}

func TestOpenFileStoreRejectsUnsafeTables(t *testing.T) {
	for _, path := range []string{"bindings.json", "/tmp/x/../bindings.json"} {
		if _, err := OpenFileStore(path); err == nil {
			t.Errorf("OpenFileStore(%q) accepted a relative or unclean path", path)
		}
	}
	s, validPath := newStore(t)
	mint(t, s, "dc-app")
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"not json":        "{",
		"trailing data":   string(valid) + "{}",
		"unknown field":   strings.Replace(string(valid), `"version"`, `"extra": 1, "version"`, 1),
		"future version":  strings.Replace(string(valid), `"version": 1`, `"version": 2`, 1),
		"bad hash":        strings.Replace(string(valid), `"token_sha256": "`, `"token_sha256": "zz`, 1),
		"bad connector":   strings.Replace(string(valid), `"connector": "codex"`, `"connector": "Codex/.."`, 1),
		"zero generation": strings.Replace(string(valid), `"generation": 1`, `"generation": 0`, 1),
		"symlink":         "",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := DefaultStorePath(dir)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if name == "symlink" {
				// A symlinked table is refused even when its target is valid.
				target := filepath.Join(dir, "elsewhere.json")
				if err := os.WriteFile(target, []byte(`{"version":1,"bindings":[]}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStore(path); err == nil {
				t.Fatal("OpenFileStore accepted an unsafe table")
			}
		})
	}
}
