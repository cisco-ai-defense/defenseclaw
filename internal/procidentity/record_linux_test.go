// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procidentity

import (
	"os"
	"strings"
	"testing"
)

// Recorded is field 22 of /proc/<pid>/stat alone, the text the gateway writes
// in gateway.pid; it is not the install-lock text of Of (boot id and ticks).
func TestRecordedIsTheBareKernelStartTheGatewayWrites(t *testing.T) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	text := string(stat)
	want := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])[19]
	got, ok := Recorded(os.Getpid())
	if !ok || got != want {
		t.Fatalf("Recorded = %q, %v; want %q", got, ok, want)
	}
	lock, _ := Of(os.Getpid())
	if lock == got || !strings.HasSuffix(lock, " "+got) {
		t.Fatalf("Of = %q is not the boot id plus Recorded %q", lock, got)
	}
	if !IsRecorded(os.Getpid(), got) {
		t.Fatal("this process is not the process its own record names")
	}
	for name, record := range map[string]string{
		"empty":                 "",
		"install-lock text":     lock,
		"another start":         got + "0",
		"another process start": "1",
	} {
		if IsRecorded(os.Getpid(), record) {
			t.Fatalf("%s: %q named this process", name, record)
		}
	}
	if IsRecorded(os.Getppid(), got) || IsRecorded(0, got) || IsRecorded(-1, got) {
		t.Fatal("a record named a process that did not start then")
	}
}
