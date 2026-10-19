// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// These tests use fake lease callbacks and ordinary inert directory handles.
// No native stage, sandbox, executable image or child process is started.
func hostStageAssetInputs(t *testing.T) bridgeprocess.Inputs {
	t.Helper()
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{}, Read: []*os.File{file}, Write: []*os.File{nil}}
}

func hostStageAssetDuplicate(t *testing.T) (func() (*os.File, error), *[]*os.File) {
	t.Helper()
	root := t.TempDir()
	files := new([]*os.File)
	t.Cleanup(func() {
		for _, file := range *files {
			_ = file.Close()
		}
	})
	return func() (*os.File, error) {
		file, err := os.Open(root)
		if file != nil {
			*files = append(*files, file)
		}
		return file, err
	}, files
}

func TestHostStageAssetsReleaseAfterAllExclusiveClosesAndRetryInUse(t *testing.T) {
	_, spec := resolved(t, "")
	inputs := hostStageAssetInputs(t)
	duplicate, files := hostStageAssetDuplicate(t)
	leaseCalls, stageCalls := 0, 0
	release := &hostStageRelease{
		closeLease: func() error {
			leaseCalls++
			for _, file := range append(append([]*os.File{}, *files...), inputs.Read...) {
				if file.Fd() != ^uintptr(0) {
					t.Fatal("lease released before an exclusive asset definitely closed")
				}
			}
			return nil
		},
		closeStage: func() error {
			stageCalls++
			if stageCalls == 1 {
				return workspace.ErrHostStageInUse
			}
			return nil
		},
	}
	assets, err := assembleHostStageAssets(context.Background(), spec.Identity, inputs, []string{"/readonly"}, []string{"/work"}, duplicate, release, nil)
	if err != nil || assets == nil || assets.cleanupOnly || len(*files) != 2 || inputs.Write[0] != nil {
		t.Fatalf("exclusive handoff mutated caller layout or failed: %v", err)
	}
	if assets.inputs.CWD == assets.inputs.Write[0] {
		t.Fatal("CWD and work use the same exclusive File")
	}
	a, errA := assets.inputs.CWD.Stat()
	b, errB := assets.inputs.Write[0].Stat()
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Fatal("independent exclusive files do not name the same held root")
	}
	if err := assets.Close(); !errors.Is(err, workspace.ErrHostStageInUse) || leaseCalls != 1 || stageCalls != 1 {
		t.Fatalf("known stage-in-use refusal was lost: %v", err)
	}
	if err := assets.Close(); err != nil || leaseCalls != 1 || stageCalls != 2 {
		t.Fatalf("stage retry reclosed exclusive files/lease or remained stranded: %v", err)
	}
	if err := assets.Close(); err != nil || stageCalls != 2 {
		t.Fatal("successful stage cleanup repeated")
	}
}

func TestHostStageAssetsPartialAllocationNeverTakesCallerInputs(t *testing.T) {
	_, spec := resolved(t, "")
	inputs := hostStageAssetInputs(t)
	duplicate, files := hostStageAssetDuplicate(t)
	failure := errors.New("fixed duplicate validation failure")
	calls, released := 0, false
	allocate := func() (*os.File, error) {
		file, err := duplicate()
		calls++
		if err == nil && calls == 2 {
			err = failure
		}
		return file, err
	}
	release := &hostStageRelease{closeLease: func() error { released = true; return nil }, closeStage: func() error { return nil }}
	assets, err := assembleHostStageAssets(context.Background(), spec.Identity, inputs, []string{"/readonly"}, []string{"/work"}, allocate, release, nil)
	if !errors.Is(err, failure) || assets == nil || !assets.cleanupOnly || len(*files) != 2 || assets.inputs.Peer != nil || len(assets.inputs.Read) != 0 {
		t.Fatal("partial handoff did not isolate newly allocated custody")
	}
	host, _ := host(t, spec.Identity.Runtime)
	if err := host.BindAssets(spec.Identity, assets); !errors.Is(err, ErrAssets) {
		t.Fatal("cleanup-only assets were admitted")
	}
	if err := assets.Close(); err != nil || !released {
		t.Fatalf("partial allocation did not release exact new custody: %v", err)
	}
	for _, file := range *files {
		if file.Fd() != ^uintptr(0) {
			t.Fatal("partial exclusive duplicate remained open")
		}
	}
	if _, err := inputs.Read[0].Stat(); err != nil {
		t.Fatal("partial handoff closed a caller-owned input")
	}
}

func TestHostStageAssetsCancellationRetainsOnlyAllocatedCustody(t *testing.T) {
	_, spec := resolved(t, "")
	inputs := hostStageAssetInputs(t)
	duplicate, files := hostStageAssetDuplicate(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allocate := func() (*os.File, error) { file, err := duplicate(); cancel(); return file, err }
	release := &hostStageRelease{closeLease: func() error { return nil }, closeStage: func() error { return nil }}
	assets, err := assembleHostStageAssets(ctx, spec.Identity, inputs, []string{"/readonly"}, []string{"/work"}, allocate, release, nil)
	if !errors.Is(err, context.Canceled) || assets == nil || !assets.cleanupOnly || len(*files) != 1 {
		t.Fatal("canceled construction published usable assets or lost allocated custody")
	}
	if err := assets.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := inputs.Read[0].Stat(); err != nil {
		t.Fatal("canceled construction consumed caller input")
	}
}

func TestHostStageAssetsUncertainExclusiveCloseRetainsStage(t *testing.T) {
	releaseCalls := 0
	assets := &Assets{cleanupOnly: true, inputs: bridgeprocess.Inputs{CWD: new(os.File)}, releaseStage: func() error { releaseCalls++; return nil }}
	first := assets.Close()
	if first == nil || assets.Close() != first || releaseCalls != 0 || assets.releaseStage == nil {
		t.Fatal("uncertain exclusive close released lease/stage or cleared its failure")
	}
}

func TestHostStageAssetsUncertainLeaseCloseRemainsSticky(t *testing.T) {
	calls, stageCalls := 0, 0
	failure := errors.New("fixed lease close uncertainty")
	release := &hostStageRelease{closeLease: func() error { calls++; return failure }, closeStage: func() error { stageCalls++; return nil }}
	assets := &Assets{cleanupOnly: true, releaseStage: release.close}
	first, second := assets.Close(), assets.Close()
	if !errors.Is(first, failure) || !errors.Is(second, failure) || calls != 1 || stageCalls != 0 {
		t.Fatal("uncertain lease release admitted stage deletion or repeated native close")
	}
}

func TestHostStageAssetsCanceledAdmissionDoesNotAcquireCustody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, spec := resolved(t, "")
	assets, err := NewHostStageAssets(ctx, spec.Identity, bridgeprocess.Inputs{}, nil, nil, nil)
	if assets != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("already canceled admission acquired ownership or continued preparation")
	}
}

func TestHostStageAssetsWrongWindowsDriverRefusedBeforeAcquisition(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows custody lane admission")
	}
	_, spec := resolved(t, "")
	spec.Identity.Runtime.HostOS, spec.Identity.Runtime.ExecutionOS = "windows", "windows"
	// Driver remains bubblewrap. A zero Stage has no native producer, so any
	// accidental acquisition would return UnsupportedPlatform instead.
	inputs := bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{}, Write: []*os.File{nil}}
	assets, err := NewHostStageAssets(context.Background(), spec.Identity, inputs, nil, []string{"/work"}, new(workspace.HostStage))
	if assets != nil || !errors.Is(err, ErrAssets) {
		t.Fatal("Windows stage handoff accepted mismatched substrate metadata")
	}
}
