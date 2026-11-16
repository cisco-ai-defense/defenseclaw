// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package procboot gives the Linux boot instant that /proc/<pid>/stat start
// times count from when /proc/stat cannot be read.
//
// A /proc mounted with subset=pid holds only the process directories and
// /proc/self; it has no /proc/stat, so its btime line is gone (GAP-2101).
// The kernel computes btime as the real-time clock minus the boot-time clock,
// in whole seconds, so the same two clocks give the same value without it.
package procboot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// FromClock returns the boot instant in Unix seconds from the clocks, the
// way the kernel computes /proc/stat btime. ok is false off Linux or when a
// clock cannot be read.
func FromClock() (seconds int64, ok bool) { return fromClock() }

// SubsetPID reports whether the procfs at procDir is a pid-only mount: it
// has no stat file but still serves the process table (self/stat). A
// directory with neither is not a usable process table, and callers keep
// treating it as unavailable.
func SubsetPID(procDir string) bool {
	if _, err := os.Lstat(filepath.Join(procDir, "stat")); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	_, err := os.Stat(filepath.Join(procDir, "self", "stat"))
	return err == nil
}
