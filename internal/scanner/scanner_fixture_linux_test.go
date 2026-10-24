// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scanner

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

// scannerFixtureRunning reports whether pid exists and is not a zombie. It
// reads /proc, so it needs no external tool; a read that fails for any
// reason other than a missing process fails the test.
func scannerFixtureRunning(t *testing.T, pid int) bool {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatalf("read state of %d: %v", pid, err)
	}
	// The state follows the parenthesized command name, which may itself
	// contain ") ".
	stat := string(raw)
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || len(strings.Fields(stat[end+1:])) == 0 {
		t.Fatalf("unparsable /proc/%d/stat: %q", pid, stat)
	}
	state := strings.Fields(stat[end+1:])[0]
	return state != "Z" && state != "X"
}
