// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxauth

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBindingExecutionOSPreservesLegacyAndNativePlatforms(t *testing.T) {
	for _, platform := range []string{"", "linux", "darwin", "windows"} {
		t.Run("guest_"+platform, func(t *testing.T) {
			spec := Spec{SandboxName: "native-platform", Connector: "codex", ExecutionOS: platform, Workdir: Workdir{Mode: WorkdirCopy}}
			normalized, err := spec.normalize()
			if err != nil {
				t.Fatal(err)
			}
			binding := bindingFromSpec("unused", normalized)
			want := platform
			if want == "" {
				want = "linux"
			}
			if binding.GuestOS() != want || binding.Spec().ExecutionOS != platform {
				t.Fatalf("platform round trip: guest=%q stored=%q", binding.GuestOS(), binding.Spec().ExecutionOS)
			}
		})
	}
	for _, platform := range []string{"Linux", " windows", "wsl", "auto", "plan9", "linux\x00"} {
		spec := Spec{SandboxName: "bad-platform", Connector: "codex", ExecutionOS: platform, Workdir: Workdir{Mode: WorkdirCopy}}
		if _, err := spec.normalize(); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("invalid execution OS %q: %v", platform, err)
		}
	}
}

func TestNativeWindowsBindingRejectsUnimplementedHostMappings(t *testing.T) {
	for _, workdir := range []Workdir{
		{Mode: WorkdirMount, Mounts: []Mount{{SandboxPath: "/work", HostPath: filepath.Join(t.TempDir(), "host")}}},
		{Mode: WorkdirCopy, Mounts: []Mount{{SandboxPath: "/context", HostPath: filepath.Join(t.TempDir(), "host")}}},
	} {
		spec := Spec{SandboxName: "windows-mapping", Connector: "codex", ExecutionOS: "windows", Workdir: workdir}
		if _, err := spec.normalize(); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("native Windows host mapping admitted: %v", err)
		}
	}
}

func TestBindingExecutionOSPersistsAndCannotChangeWithLiveCredential(t *testing.T) {
	file := filepath.Join(t.TempDir(), "private-bindings", "bindings.json")
	store, err := OpenFileStore(file)
	if err != nil {
		t.Fatal(err)
	}
	binding, token, err := store.Mint(Spec{SandboxName: "native-platform", Connector: "codex", ExecutionOS: "windows", Workdir: Workdir{Mode: WorkdirCopy}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenFileStore(file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Match(token)
	if err != nil || got.ExecutionOS != "windows" {
		t.Fatalf("persisted execution OS lost: %q, %v", got.ExecutionOS, err)
	}
	if _, err := store.Update(binding.ID, func(spec *Spec) error { spec.ExecutionOS = "linux"; return nil }); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("changed a live binding's execution OS: %v", err)
	}
	if got, err := store.Match(token); err != nil || got.ExecutionOS != "windows" {
		t.Fatalf("failed platform update changed credential: %q, %v", got.ExecutionOS, err)
	}
	rotated, newToken, err := store.Rotate(binding.ID)
	if err != nil || rotated.ExecutionOS != "windows" {
		t.Fatalf("credential rotation changed platform: %q, %v", rotated.ExecutionOS, err)
	}
	if _, err := store.Match(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old credential survived rotation: %v", err)
	}
	if got, err := store.Match(newToken); err != nil || got.ExecutionOS != "windows" {
		t.Fatalf("rotated credential lost platform: %q, %v", got.ExecutionOS, err)
	}
	if err := store.Revoke(binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Match(newToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("credential survived revocation: %v", err)
	}
}
