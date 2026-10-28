// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1074: on Linux and macOS the lifecycle's run marker is the marker. It
// is held when it exists as any file type, and when its state cannot be
// read for any reason but its absence; the hook reads the layout's path.
func TestManagedLifecycleMarkerOnLinuxAndMacOS(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err == nil {
		if got := managedLifecycleMarkerPath(); got != layout.LifecycleMarkerPath || got == "" {
			t.Fatalf("marker path %q, want the layout's %q", got, layout.LifecycleMarkerPath)
		}
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "defenseclaw-lifecycle.active")
	previous := managedLifecycleMarkerPath
	managedLifecycleMarkerPath = func() string { return marker }
	t.Cleanup(func() { managedLifecycleMarkerPath = previous })
	opts := Options{ManagedEnterprise: true}
	if managedLifecycleActive(opts) {
		t.Fatal("no marker reads as a lifecycle run (control)")
	}
	for _, kind := range []struct {
		name string
		make func(t *testing.T)
	}{
		{"file", func(t *testing.T) {
			if err := os.WriteFile(marker, []byte("1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"dangling symlink", func(t *testing.T) {
			if err := os.Symlink(filepath.Join(dir, "missing"), marker); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T) {
			if err := os.Mkdir(marker, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(kind.name, func(t *testing.T) {
			kind.make(t)
			t.Cleanup(func() { _ = os.RemoveAll(marker) })
			if !managedLifecycleActive(opts) {
				t.Fatal("the marker is not held")
			}
		})
	}
	if os.Geteuid() != 0 {
		t.Run("unsearchable directory", func(t *testing.T) {
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			if !managedLifecycleActive(opts) {
				t.Fatal("a marker whose state cannot be read is not held")
			}
		})
	}
	for goos, want := range map[string]string{
		"linux":  "/run/defenseclaw-lifecycle.active",
		"darwin": "/var/run/defenseclaw-lifecycle.active",
	} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil || layout.LifecycleMarkerPath != want {
			t.Fatalf("%s marker %q (%v), want %q", goos, layout.LifecycleMarkerPath, err, want)
		}
	}
}
