// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"io/fs"
	"os"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedLifecycleHeld reads the Linux and macOS lifecycle marker: the run
// marker of the enterprise lifecycle (managedLifecycleActive). A variable
// for tests.
var managedLifecycleHeld = func(Options) bool {
	return lifecycleMarkerHeld(managedLifecycleMarkerPath())
}

// managedLifecycleMarkerPath is this platform's lifecycle run marker
// (managed.StandaloneLayout.LifecycleMarkerPath); a variable for tests.
var managedLifecycleMarkerPath = func() string {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return ""
	}
	return layout.LifecycleMarkerPath
}

// lifecycleMarkerHeld reports a marker that exists, as any file type, or
// whose state cannot be read for any reason but its absence, as the
// per-user install lock (installLockHeldBy).
func lifecycleMarkerHeld(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}
