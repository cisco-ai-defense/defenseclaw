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
	s, err := OpenFileStore(path, opts...)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	return s, path
}

func TestMintMatchAndPersistence(t *testing.T) {
	s, path := newStore(t)
	b, token, err := s.Mint(mountSpec("dc-claude-app", "claudecode"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !LooksLikeToken(token) {
		t.Fatalf("token %q has the wrong shape", token)
	}
	if b.TokenHash != HashToken(token) || b.Generation != 1 || b.ID == "" {
		t.Fatalf("binding = %+v", b)
	}
	got, err := s.Match(token)
	if err != nil || got.ID != b.ID {
		t.Fatalf("Match = %+v, %v", got, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), strings.TrimPrefix(token, TokenPrefix)) {
		t.Fatal("binding table contains the credential")
	}
	if !strings.Contains(string(data), b.TokenHash) {
		t.Fatal("binding table is missing the credential hash")
	}
	assertMode(t, path, 0o600)
	assertMode(t, filepath.Dir(path), 0o700)

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, err := reopened.Match(token); err != nil || got.ID != b.ID {
		t.Fatalf("reopened Match = %+v, %v", got, err)
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

func TestMatchRejects(t *testing.T) {
	s, _ := newStore(t)
	_, token, err := s.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	for _, presented := range []string{
		"", "Bearer " + token, token + "x", strings.ToUpper(token), TokenPrefix + strings.Repeat("A", 43),
		"openshell:resolve:env:v1_DEFENSECLAW_SANDBOX_TOKEN", strings.Repeat("a", 64),
	} {
		if _, err := s.Match(presented); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Match(%q) = %v, want ErrUnauthenticated", presented, err)
		}
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

func TestRotateInvalidatesPreviousCredential(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newToken == oldToken || rotated.Generation != 2 || rotated.TokenHash == b.TokenHash {
		t.Fatalf("rotation did not replace the credential: %+v", rotated)
	}
	if !rotated.ExpiresAt.Equal(clock.Now().Add(time.Hour)) {
		t.Fatalf("rotation must restart the ttl window, expires %v", rotated.ExpiresAt)
	}
	if _, err := s.Match(oldToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old credential after rotate: %v", err)
	}
	if got, err := s.Match(newToken); err != nil || got.Generation != 2 {
		t.Fatalf("new credential: %+v %v", got, err)
	}
	if _, _, err := s.Rotate("sb_ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate unknown: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	s, _ := newStore(t)
	b, token, err := s.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(b.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked credential: %v", err)
	}
	if err := s.Revoke(b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := s.Get(b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get revoked: %v", err)
	}
	// The name is free again once revoked.
	if _, _, err := s.Mint(mountSpec("dc-app", "codex")); err != nil {
		t.Fatalf("re-mint after revoke: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	clock := newTestClock()
	s, _ := newStore(t, WithClock(clock.Now))
	spec := mountSpec("dc-app", "codex")
	spec.TTL = time.Minute
	_, token, err := s.Mint(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Match(token); err != nil {
		t.Fatalf("live credential: %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := s.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired credential: %v", err)
	}
}

func TestUpdate(t *testing.T) {
	s, _ := newStore(t)
	b, token, err := s.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.Update(b.ID, func(spec *Spec) error {
		spec.SandboxID = "0f5c7a3e-1111-2222-3333-444455556666"
		spec.HookContractID = "codex-hooks-v4"
		return nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.SandboxID == "" || updated.TokenHash != b.TokenHash || updated.Generation != b.Generation {
		t.Fatalf("updated = %+v", updated)
	}
	if got, err := s.Match(token); err != nil || got.HookContractID != "codex-hooks-v4" {
		t.Fatalf("Match after update = %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*Spec) error{
		"connector": func(spec *Spec) error { spec.Connector = "claudecode"; return nil },
		"name":      func(spec *Spec) error { spec.SandboxName = "dc-renamed"; return nil },
		"invalid":   func(spec *Spec) error { spec.Workdir.Mode = "bogus"; return nil },
	} {
		if _, err := s.Update(b.ID, mutate); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("update %s: %v", name, err)
		}
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
		if _, _, err := s.Mint(mountSpec(name, "codex")); err != nil {
			t.Fatal(err)
		}
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
	b, err := OpenFileStore(path, WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	binding, token, err := a.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Match(token); err != nil || got.ID != binding.ID {
		t.Fatalf("second store did not see mint: %+v %v", got, err)
	}
	if err := b.Revoke(binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("first store still honours a revoked credential: %v", err)
	}
}

func TestRefreshIntervalBoundsDiskChecks(t *testing.T) {
	clock := newTestClock()
	a, path := newStore(t, WithClock(clock.Now), WithRefreshInterval(time.Second))
	other, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := other.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("store refreshed before its interval: %v", err)
	}
	clock.Advance(time.Second)
	if _, err := a.Match(token); err != nil {
		t.Fatalf("store did not refresh after its interval: %v", err)
	}
}

func TestConcurrentWritersAcrossStores(t *testing.T) {
	a, path := newStore(t)
	b, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
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
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(reopened.List()); n != 40 {
		t.Fatalf("lost updates: %d bindings, want 40", n)
	}
}

func TestTamperedTableFailsClosed(t *testing.T) {
	s, path := newStore(t, WithRefreshInterval(0))
	_, token, err := s.Mint(mountSpec("dc-app", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("world-readable table still authenticates: %v", err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("OpenFileStore accepted a world-readable table")
	}
	if _, _, err := s.Mint(mountSpec("dc-other", "codex")); err == nil {
		t.Fatal("Mint overwrote a tampered table")
	}
}

func TestCorruptTablesAreRejected(t *testing.T) {
	valid := func(t *testing.T) string {
		s, path := newStore(t)
		if _, _, err := s.Mint(mountSpec("dc-app", "codex")); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for name, mutate := range map[string]func(string) string{
		"not json":       func(string) string { return "{" },
		"trailing data":  func(s string) string { return s + "{}" },
		"unknown field":  func(s string) string { return strings.Replace(s, `"version"`, `"extra": 1, "version"`, 1) },
		"future version": func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 2`, 1) },
		"bad hash":       func(s string) string { return strings.Replace(s, `"token_sha256": "`, `"token_sha256": "zz`, 1) },
		"bad connector":  func(s string) string { return strings.Replace(s, `"connector": "codex"`, `"connector": "Codex/.."`, 1) },
		"zero generation": func(s string) string {
			return strings.Replace(s, `"generation": 1`, `"generation": 0`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := DefaultStorePath(dir)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(mutate(valid(t))), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStore(path); err == nil {
				t.Fatal("OpenFileStore accepted a corrupt table")
			}
		})
	}
}

func TestOpenFileStoreRejectsRelativePath(t *testing.T) {
	if _, err := OpenFileStore("bindings.json"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := OpenFileStore("/tmp/x/../bindings.json"); err == nil {
		t.Fatal("unclean path accepted")
	}
}

func TestSymlinkedTableIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := DefaultStorePath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"bindings":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("symlinked binding table accepted")
	}
}
