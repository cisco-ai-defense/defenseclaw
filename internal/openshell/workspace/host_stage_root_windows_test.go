// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// This is an inert native filesystem test. It launches no program or sandbox
// and changes ACLs only through the existing creator for new private fixtures.
func TestHostStageWindowsRootLeaseHeldObjectAndCleanupBarrier(t *testing.T) {
	opts := hostStageFixture(t)
	const content = "fixed public staged root bytes"
	writeHostStageFixture(t, opts.Project, "public.txt", content)
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	var leases []*RootLease
	t.Cleanup(func() {
		for _, lease := range leases {
			if err := lease.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	})
	// Changing display metadata must not select the root for native handoff.
	stage.mu.Lock()
	stage.record.Stage = filepath.Join(opts.DataDir, "nonexistent-display-path")
	stage.mu.Unlock()
	var files []*os.File
	var expectedID string
	for range 2 {
		lease, err := stage.AcquireRoot()
		if lease != nil {
			leases = append(leases, lease)
		}
		if err != nil {
			t.Fatal(err)
		}
		file, err := lease.File()
		if err != nil {
			t.Fatal(err)
		}
		id, err := windowsHostStageIdentity(file)
		if err != nil || expectedID != "" && id != expectedID {
			t.Fatalf("root duplicate native identity: %v", err)
		}
		expectedID = id
		flags, err := windowsHostStageLeaseHandleFlags(file)
		if err != nil || flags&windows.HANDLE_FLAG_INHERIT != 0 {
			t.Fatalf("root duplicate inheritance: %v", err)
		}
		if err := safefile.ValidatePrivateHandle(windows.Handle(file.Fd())); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	read := func(file *os.File) {
		t.Helper()
		child, err := openWindowsHostStageChild(file, "public.txt", windows.FILE_SHARE_READ)
		if err != nil {
			t.Fatal(err)
		}
		value, readErr := io.ReadAll(io.LimitReader(child, 128))
		if err := errors.Join(readErr, child.Close()); err != nil || string(value) != content {
			t.Fatalf("held sanitized child bytes changed: %q, %v", value, err)
		}
	}
	read(files[0])
	if err := stage.Close(); !errors.Is(err, ErrHostStageInUse) {
		t.Fatalf("premature cleanup did not refuse: %v", err)
	}
	// Decisive regression: recursive deletion must not have removed children
	// before encountering an open root handle. Existing borrowed custody works.
	read(files[0])
	read(files[1])
	if lease, err := stage.AcquireRoot(); lease != nil || err == nil {
		t.Fatal("close request admitted another root consumer")
	}
	if _, err := stage.TreePath(); err == nil {
		t.Fatal("close request retained path handoff")
	}
	if err := leases[0].Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := leases[0].File(); err == nil {
		t.Fatal("released root remained borrowable")
	}
	if err := stage.Close(); !errors.Is(err, ErrHostStageInUse) {
		t.Fatal("cleanup overtook the second consumer")
	}
	read(files[1])
	if err := leases[1].Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoHostStageResidue(t, opts)
}
