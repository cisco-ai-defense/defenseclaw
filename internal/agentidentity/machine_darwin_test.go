// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package agentidentity

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The machine id is the IOPlatformUUID that IOKit publishes. The kern.uuid
// sysctl (the kernel build UUID) is shared by every Mac on one macOS build.
func TestReadPlatformMachineIDIsIOPlatformUUID(t *testing.T) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		t.Skipf("ioreg: %v", err)
	}
	want := regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]{36})"`).FindSubmatch(out)
	if want == nil {
		t.Fatalf("ioreg printed no IOPlatformUUID")
	}
	got, err := readPlatformMachineID()
	if err != nil {
		t.Fatalf("readPlatformMachineID: %v", err)
	}
	if !strings.EqualFold(got, string(want[1])) {
		t.Fatalf("machine id = %q, want IOPlatformUUID %q", got, want[1])
	}
}
