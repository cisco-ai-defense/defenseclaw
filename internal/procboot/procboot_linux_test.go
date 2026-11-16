// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procboot

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// GAP-2101: the clock-derived boot instant is the kernel's btime, so a start
// time computed under a subset=pid /proc names the same instant as one
// computed from /proc/stat.
func TestFromClockMatchesProcStatBtime(t *testing.T) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		t.Skipf("no /proc/stat here: %v", err)
	}
	var btime int64
	for _, line := range strings.Split(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			btime, _ = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		}
	}
	if btime == 0 {
		t.Skip("no btime line")
	}
	got, ok := FromClock()
	if !ok {
		t.Fatal("FromClock failed on Linux")
	}
	if d := got - btime; d < -1 || d > 1 {
		t.Fatalf("FromClock = %d, /proc/stat btime = %d", got, btime)
	}
}

func TestSubsetPIDNeedsTheProcessTableAndNoStat(t *testing.T) {
	root := t.TempDir()
	if SubsetPID(root) {
		t.Fatal("an empty directory is not a process table")
	}
	if err := os.MkdirAll(root+"/self", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/self/stat", []byte("1 (x) S 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !SubsetPID(root) {
		t.Fatal("self/stat without stat is a subset=pid mount")
	}
	if err := os.WriteFile(root+"/stat", []byte("btime 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if SubsetPID(root) {
		t.Fatal("a full /proc is not a subset=pid mount")
	}
}
