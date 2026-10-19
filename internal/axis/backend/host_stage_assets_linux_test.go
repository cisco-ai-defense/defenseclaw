// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"golang.org/x/sys/unix"
)

// Filesystem custody only: empty Image values are never sealed or executed.
func TestHostStageAssetsLinuxHeldDuplicatesAndCleanupRetry(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "operator-home")
	project, data := filepath.Join(home, "project"), filepath.Join(base, "private-data")
	for _, name := range []string{project, data} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "public.txt"), []byte("fixed public asset bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := workspace.PrepareHostStage(context.Background(), workspace.StageOptions{Name: "linux-assets", Project: project, DataDir: data, Home: home, MaxBytes: 1 << 20})
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
	tree, err := stage.TreePath() // oracle only; no path passed to Assets
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
	inputs := bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{}, Write: []*os.File{nil}}
	assets, err = NewHostStageAssets(context.Background(), spec.Identity, inputs, nil, []string{"/work"}, stage)
	if err != nil {
		t.Fatal(err)
	}
	var original unix.Stat_t
	if err := unix.Fstat(int(borrowed.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{assets.inputs.CWD, assets.inputs.Write[0]} {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Dev != original.Dev || stat.Ino != original.Ino || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
			t.Fatal("exclusive Linux root copy changed held identity or private mode")
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 || file.Fd() == borrowed.Fd() {
			t.Fatal("Linux adapter reused borrowed descriptor or made it inheritable")
		}
	}
	if assets.inputs.CWD.Fd() == assets.inputs.Write[0].Fd() {
		t.Fatal("CWD and work copies do not have exclusive descriptor custody")
	}
	if err := assets.Close(); !errors.Is(err, workspace.ErrHostStageInUse) {
		t.Fatal("another lease did not block stage deletion")
	}
	for _, file := range []*os.File{assets.inputs.CWD, assets.inputs.Write[0]} {
		if file.Fd() != ^uintptr(0) {
			t.Fatal("exclusive file remained open during stage close retry")
		}
	}
	if value, err := os.ReadFile(filepath.Join(tree, "public.txt")); err != nil || string(value) != "fixed public asset bytes" {
		t.Fatal("in-use cleanup deleted the other consumer's child")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if err := assets.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
		t.Fatal("explicit asset cleanup retry left owned stage residue")
	}
}
