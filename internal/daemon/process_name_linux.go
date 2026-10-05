// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Package init runs on the main thread, whose name is the process name.
func init() { restoreProcessName() }

// restoreProcessName gives a daemon child started from /proc/self/exe
// (daemonExecPath) its install name back. The kernel names such a process
// "exe", which hides the gateway from ps/pgrep checks, the installer's
// restart and health gate, and port-holder messages. argv[0] keeps the
// install path, so take the name from there.
func restoreProcessName() {
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil || strings.TrimSpace(string(comm)) != "exe" || len(os.Args) == 0 {
		return
	}
	name := filepath.Base(os.Args[0])
	if name == "exe" || name == "." || name == string(filepath.Separator) {
		return
	}
	if ptr, err := unix.BytePtrFromString(name); err == nil {
		_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(ptr)), 0, 0, 0)
	}
}
