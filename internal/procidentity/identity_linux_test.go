// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procidentity

import (
	"os"
	"strings"
	"testing"
)

// Of reads the boot id and field 22 of /proc/<pid>/stat.
func TestOfNamesBootAndKernelStart(t *testing.T) {
	identity, ok := Of(os.Getpid())
	if !ok {
		t.Fatal("no identity for this process")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	text := string(stat)
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
	if want := strings.TrimSpace(string(boot)) + " " + fields[19]; identity != want {
		t.Fatalf("Of = %q, want %q", identity, want)
	}
	if _, ok := Of(2147483647); ok {
		t.Fatal("an identity for a pid that names no process")
	}
}
