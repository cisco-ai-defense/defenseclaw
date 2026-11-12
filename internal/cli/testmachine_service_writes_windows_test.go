// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A standard user cannot list the hook guardian's state folder, and the
// guardian's rewrites in it move the folder's modified time every pass. The
// service-folder fingerprint of a folder this identity cannot list leaves
// that time out, so a standard-user run is not failed by the guardian's own
// passes (GAP-0093, REVIEW-g672 L2). The fixture denies only
// FILE_LIST_DIRECTORY to the test account, which can still write a file in
// it, as the service does.
func TestTestMachineServiceFolderThisIdentityCannotListIgnoresTheServicesPasses(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "hook-guardian-state")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve the test account: %v", err)
	}
	me := user.User.Sid.String()
	setDACL := func(sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(locked, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatalf("set the DACL of %s: %v", locked, err)
		}
	}
	allow := "(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	setDACL("D:P(D;;0x1;;;" + me + ")" + allow) // 0x1: FILE_LIST_DIRECTORY
	t.Cleanup(func() { setDACL("D:P" + allow) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("this token lists the folder through the deny entry (its backup privilege is enabled); a standard user cannot")
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(locked, past, past); err != nil {
		t.Fatal(err)
	}
	folders := testServiceFolders{roots: []string{locked}}
	snapshot := func(before map[string]string) map[string]string {
		folders.before = before
		out := map[string]string{}
		fingerprintTestServiceFolders(out, folders)
		return out
	}
	before := snapshot(nil)
	if got := before["file "+locked]; !strings.HasPrefix(got, "service folder, contents unreadable: ") {
		t.Fatalf("unlistable service folder fingerprint %q, want an unreadable note without its time", got)
	}
	// The guardian's pass: a record replaced in the folder, which moves its
	// modified time.
	if err := os.WriteFile(filepath.Join(locked, "activation.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != 0 {
		t.Fatalf("the service's pass in a folder this identity cannot list is reported as a test's write: %v", changes)
	}
}

// GAP-0093 (round 3, review 2 L2): as LocalSystem the temp folder is
// C:\Windows\SystemTemp whatever TMP says, so a t.TempDir() is
// C:\Windows\SystemTemp\TestXxxNNN\001, which neither of the run's two
// folders names. A service log line that names only that path is still a
// test's write; a line of the services' own is not.
func TestTestRunMarkersCatchASystemTempTestFolder(t *testing.T) {
	const systemTemp = `C:\Windows\SystemTemp`
	runDirs := []string{systemTemp + `\defenseclaw-cli-run-7`, systemTemp + `\defenseclaw-cli-test-7`}
	markers := testRunMarkersIn(runDirs, `Software\DefenseClaw-test-7`, "cli.test.exe", systemTemp)
	found := false
	for _, marker := range markers {
		found = found || marker == systemTemp+`\Test`
	}
	if !found {
		t.Fatalf("LocalSystem's run markers %q do not include %s\\Test", markers, systemTemp)
	}
	// A run whose TMP was honoured has the temp folder to itself.
	for _, marker := range testRunMarkersIn(runDirs, `Software\DefenseClaw-test-7`, "cli.test.exe", runDirs[0]) {
		if strings.HasSuffix(marker, `\Test`) {
			t.Fatalf("a run with its own temp folder has the marker %q", marker)
		}
	}

	dir := t.TempDir()
	log := filepath.Join(dir, "hook-guardian.log")
	base := "[hook-guardian] reconcile reason=interval status=ok users=3\n"
	snapshot := func(before map[string]string) map[string]string {
		out := map[string]string{}
		fingerprintTestServiceFolders(out, testServiceFolders{roots: []string{dir}, before: before, runMarkers: markers})
		return out
	}
	for _, tc := range []struct {
		name, line string
		want       int
	}{
		{"the services' own lines", base + "[hook-guardian] staged " + systemTemp + "\\defenseclaw-stage-1\\a.ps1\n", 0},
		{"a line naming only a test's temp folder", "[hook-guardian] warn: restored " + systemTemp + "\\TestFoo123\\001\\x.json\n", 1},
		{"the same in another case", "[hook-guardian] warn: " + strings.ToLower(systemTemp) + "\\testfoo123\\001\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(log, []byte(base), 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshot(nil)
			time.Sleep(20 * time.Millisecond) // a later modification time
			file, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(tc.line); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if changes := diffTestMachineRegistry(before, snapshot(before)); len(changes) != tc.want {
				t.Fatalf("%d changes, want %d:\n%s", len(changes), tc.want, strings.Join(changes, "\n"))
			}
		})
	}
}
