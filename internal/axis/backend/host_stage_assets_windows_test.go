// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// This fixture performs only native filesystem custody operations. No image,
// native peer, child process or sandbox is started, and ACL creation applies
// only to the fresh test-owned private data directory.
func TestHostStageAssetsWindowsHeldDuplicatesAndCleanupRetry(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "synthetic-home")
	project, data := filepath.Join(home, "project"), filepath.Join(root, "private-data")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if created, err := safefile.CreatePrivateDirectory(data); err != nil || !created {
		t.Fatalf("create new private fixture: %v", err)
	}
	const content = "fixed public host stage asset bytes"
	if err := os.WriteFile(filepath.Join(project, "public.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := workspace.PrepareHostStage(context.Background(), workspace.StageOptions{Name: "asset-fixture", Project: project, DataDir: data, Home: home, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var assets *Assets
	var other *workspace.RootLease
	t.Cleanup(func() {
		if other != nil {
			_ = other.Close()
		}
		if assets != nil {
			if err := assets.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	})
	// This saved path is a test oracle only. The adapter receives no path and
	// selects neither duplicate by this spelling.
	tree, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	other, err = stage.AcquireRoot()
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := other.File()
	if err != nil {
		t.Fatal(err)
	}
	_, spec := resolved(t, "")
	spec.Identity.Runtime.HostOS, spec.Identity.Runtime.ExecutionOS, spec.Identity.Runtime.Driver = "windows", "windows", "process_container"
	inputs := bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{}, Write: []*os.File{nil}}
	assets, err = NewHostStageAssets(context.Background(), spec.Identity, inputs, nil, []string{"/work"}, stage)
	if err != nil {
		t.Fatal(err)
	}
	type rootID struct {
		volume uint64
		id     [16]byte
	}
	var expected rootID
	getFlags := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	if err := getFlags.Find(); err != nil {
		t.Fatal(err)
	}
	for i, file := range []*os.File{borrowed, assets.inputs.CWD, assets.inputs.Write[0]} {
		var id rootID
		if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			expected = id
		} else if id != expected {
			t.Fatal("exclusive duplicate changed full native root identity")
		}
		var flags uint32
		ok, _, _ := getFlags.Call(file.Fd(), uintptr(unsafe.Pointer(&flags)))
		runtime.KeepAlive(file)
		if ok == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 {
			t.Fatal("exclusive root duplicate is inheritable or unverifiable")
		}
		if err := safefile.ValidatePrivateHandle(windows.Handle(file.Fd())); err != nil {
			t.Fatal(err)
		}
	}
	if assets.inputs.CWD == assets.inputs.Write[0] || assets.inputs.CWD == borrowed || assets.inputs.Write[0] == borrowed {
		t.Fatal("adapter transferred a borrowed handle rather than independent copies")
	}
	if err := assets.Close(); !errors.Is(err, workspace.ErrHostStageInUse) {
		t.Fatalf("another consumer did not retain stage cleanup: %v", err)
	}
	for _, file := range []*os.File{assets.inputs.CWD, assets.inputs.Write[0]} {
		if file.Fd() != uintptr(windows.InvalidHandle) {
			t.Fatal("exclusive duplicate did not close before lease/stage release")
		}
	}
	value, err := os.ReadFile(filepath.Join(tree, "public.txt"))
	if err != nil || string(value) != content {
		t.Fatal("stage-in-use cleanup deleted or changed the still-borrowed child")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if err := assets.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(data)
	if err != nil || len(entries) != 0 {
		t.Fatal("explicit retry left owned stage residue")
	}
}
