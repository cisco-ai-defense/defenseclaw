// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBoundedLifecycleTailKeepsTheResult(t *testing.T) {
	result := []byte(`{"schema_version":1,"action":"install","ok":true}` + "\n")
	short := append([]byte("WARNING: x\n"), result...)
	if got, truncated := boundedLifecycleTail(short, maximumLifecycleOutput); truncated || !bytes.Equal(got, short) {
		t.Fatalf("short output changed: truncated=%t", truncated)
	}
	noise := bytes.Repeat([]byte("WARNING: noisy line\n"), (maximumLifecycleOutput/20)+100)
	long := append(append([]byte{}, noise...), result...)
	got, truncated := boundedLifecycleTail(long, maximumLifecycleOutput)
	if !truncated {
		t.Fatal("oversized output was not reported as truncated")
	}
	if len(got) > maximumLifecycleOutput {
		t.Fatalf("tail is %d bytes, over the %d limit", len(got), maximumLifecycleOutput)
	}
	if !bytes.HasSuffix(got, result) {
		t.Fatal("tail dropped the lifecycle result")
	}
	if !bytes.HasPrefix(got, []byte("WARNING: noisy line\n")) {
		t.Fatalf("tail does not start at a line boundary: %q", got[:40])
	}
	oneLine := bytes.Repeat([]byte("x"), 64)
	if got, truncated := boundedLifecycleTail(oneLine, 16); !truncated || len(got) != 16 {
		t.Fatalf("single long line tail = %d bytes truncated=%t", len(got), truncated)
	}
}

func TestStagingBlockedPrereqNamesControlledFolderAccess(t *testing.T) {
	line := stagingBlockedPrereq(
		`C:\Deploy\DefenseClawSetup-Enterprise-x64.exe`,
		[]string{`C:\ProgramData`, `C:\ProgramData\Cisco`},
		errors.New("Access is denied."),
	)
	for _, want := range []string{
		`defenseclaw_prereq check="staging_directory" error="Access is denied."`,
		`path="C:\\ProgramData;C:\\ProgramData\\Cisco"`,
		"Controlled Folder Access",
		`Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\\Deploy\\DefenseClawSetup-Enterprise-x64.exe'`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("prereq %q is missing %q", line, want)
		}
	}
	if strings.Contains(stagingBlockedPrereq("", []string{`C:\ProgramData`}, nil), `error=`) {
		t.Fatal("an empty cause was rendered")
	}
}
