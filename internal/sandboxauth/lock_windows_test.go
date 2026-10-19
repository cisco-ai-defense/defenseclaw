// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandboxauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func windowsStoreForTest(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := DefaultStorePath(t.TempDir())
	store, err := OpenFileStore(path, WithRefreshInterval(0))
	if err != nil {
		t.Fatalf("open private binding store: %v", err)
	}
	return store, path
}

func windowsBindingSpec(name string) Spec {
	return Spec{
		SandboxName:    name,
		Connector:      "claudecode",
		ExecutionOS:    "windows",
		HookContractID: "claudecode-hooks-v1",
		Workdir:        Workdir{Mode: WorkdirCopy},
	}
}

func TestWindowsBindingStoreMintRotateRevokeAndReopen(t *testing.T) {
	store, path := windowsStoreForTest(t)
	first, credential, err := store.Mint(windowsBindingSpec("windows-one"))
	if err != nil {
		t.Fatalf("mint binding: %v", err)
	}
	if first.TokenHash != HashToken(credential) || first.Generation != 1 {
		t.Fatal("minted binding did not retain the credential hash and initial generation")
	}
	second, err := OpenFileStore(path, WithRefreshInterval(0))
	if err != nil {
		t.Fatalf("reopen binding store: %v", err)
	}
	if got, err := second.Match(credential); err != nil || got.ID != first.ID {
		t.Fatalf("reopened store did not authenticate the binding: %v", err)
	}
	rotated, nextCredential, err := second.Rotate(first.ID)
	if err != nil || rotated.Generation != 2 || nextCredential == credential {
		t.Fatalf("rotate binding: %v", err)
	}
	if _, err := store.Match(credential); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old credential remained valid after cross-instance rotation: %v", err)
	}
	if got, err := store.Match(nextCredential); err != nil || got.ID != first.ID {
		t.Fatalf("new credential did not authenticate: %v", err)
	}
	if err := store.Revoke(first.ID); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if _, err := second.Match(nextCredential); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked credential remained valid across stores: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")); err != nil {
		t.Fatalf("persistent lock sentinel is missing: %v", err)
	}
}

func TestWindowsBindingStoreCrossInstanceWrites(t *testing.T) {
	first, path := windowsStoreForTest(t)
	second, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("second binding store: %v", err)
	}
	var workers sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			store := first
			if i%2 == 1 {
				store = second
			}
			name := fmt.Sprintf("windows-concurrent-%02d", i)
			_, _, err := store.Mint(windowsBindingSpec(name))
			errs <- err
		}(i)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("cross-instance writers did not finish")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("cross-instance mint: %v", err)
		}
	}
	third, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("reopen concurrent store: %v", err)
	}
	if got := len(third.List()); got != 16 {
		t.Fatalf("serialized writers retained %d bindings, want 16", got)
	}
}

func TestWindowsBindingLockRefusesLinks(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			_, path := windowsStoreForTest(t)
			lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
			other := filepath.Join(filepath.Dir(path), "other-lock")
			if err := os.WriteFile(other, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "symlink" {
				err = os.Symlink(other, lockPath)
			} else {
				err = os.Link(other, lockPath)
			}
			if err != nil {
				t.Skipf("this Windows fixture cannot create %s: %v", kind, err)
			}
			if release, err := lockExclusive(lockPath); err == nil {
				release()
				t.Fatalf("binding lock accepted a %s", kind)
			}
		})
	}
}
