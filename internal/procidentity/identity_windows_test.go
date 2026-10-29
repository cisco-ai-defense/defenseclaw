// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procidentity

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The Windows record is the creation FILETIME, as install.ps1 and both
// plugins print it with PowerShell.
func TestOfIsTheStartTimePowerShellPrints(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	powerShell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	for _, pid := range []int{os.Getpid(), os.Getppid()} {
		identity, ok := Of(pid)
		if !ok {
			t.Fatalf("no identity for pid %d", pid)
		}
		out, err := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-Process -Id "+strconv.Itoa(pid)+" -ErrorAction Stop).StartTime.ToFileTimeUtc()").Output()
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.TrimSpace(string(out)); identity != want {
			t.Fatalf("Of(%d) = %q, PowerShell = %q", pid, identity, want)
		}
	}
}
