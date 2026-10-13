// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0421: every account can read the Application log (and the DefenseClaw
// log), so an event lists the codes of its errors and warnings, never their
// text, which names other accounts, their SIDs, home folders and guardrail
// profiles.
func TestWindowsEnterpriseEventNamesNoAccount(t *testing.T) {
	result := enterprisestatus.New("ensure", "standalone", "windows", "1.0.51")
	result.AddWarning("agent_unprotected", `claudecode for user ent-hank (S-1-5-21-1-2-3-1115) is not protected: C:\Users\ent-hank\.local\bin\claude.exe (profile offline-floor)`)
	result.AddWarning("agent_unprotected", "codex for user ent-gina (S-1-5-21-1-2-3-1116) is not protected")
	result.AddError("invalid_arguments", "guardrail.profiles contractors, engineering and sandbox-admins")
	result.Finish("windows", 0)
	message := windowsEnterpriseEventMessage(result)
	for _, leaked := range []string{"ent-hank", "ent-gina", "S-1-5-21-", `C:\Users`, "offline-floor", "contractors", "sandbox-admins"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("event message names %q:\n%s", leaked, message)
		}
	}
	if !strings.Contains(message, "\r\nerror invalid_arguments\r\n") || !strings.Contains(message, "\r\nwarning agent_unprotected (x2)\r\n") ||
		!strings.Contains(message, windowsEnterpriseLogName) {
		t.Fatalf("event message does not list the codes and where the details are:\n%s", message)
	}
}

// GAP-0421: the lifecycle log folder an earlier release created let
// BUILTIN\Users read every result. A lifecycle run leaves the folder, and the
// files already in it, to SYSTEM, Administrators and Event Log Readers.
func TestWindowsEnterpriseLogDirectoryClosesUsersRead(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the protected folder is readable only by SYSTEM, Administrators and Event Log Readers")
	}
	directory := filepath.Join(t.TempDir(), "DefenseClaw")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	earlier, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := earlier.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, windowsEnterpriseLogName)
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsEnterpriseLogDirectory(directory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, file} {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		text := descriptor.String()
		if strings.Contains(text, ";;;BU)") || !(strings.Contains(text, ";;;ER)") || strings.Contains(text, ";;;S-1-5-32-573)")) {
			t.Fatalf("%s DACL %s, want no Users entry and Event Log Readers read", path, text)
		}
	}
}
