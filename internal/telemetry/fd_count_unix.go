// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package telemetry

import (
	"os"
	"path/filepath"
	"runtime"
)

func countOpenFDs() int64 {
	switch runtime.GOOS {
	case "linux":
		ents, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return int64(len(ents))
	case "darwin", "freebsd", "openbsd", "netbsd":
		// Per-process FD directory on BSD/macOS.
		ents, err := os.ReadDir(filepath.Join("/dev/fd"))
		if err != nil {
			return -1
		}
		return int64(len(ents))
	default:
		return -1
	}
}
