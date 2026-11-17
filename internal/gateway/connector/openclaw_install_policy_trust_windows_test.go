//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1139: OpenClaw refuses an install policy command when a folder above
// it lets standard users add entries (the default ACL of C:\), so setup must
// not write such a command: OpenClaw then refuses every install.
func TestOpenClawInstallPolicyPathTrustedWindowsRefusesOpenAncestor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dir, "defenseclaw-gateway.exe")
	if err := os.WriteFile(command, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// BUILTIN\Users may create folders in dir, as on a drive root; the
	// file inherits only trusted entries.
	sd, err := windows.SecurityDescriptorFromString("D:(A;CI;0x4;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	err = openClawInstallPolicyPathTrusted(command, "", "2026.11.3")
	if err == nil || !strings.HasPrefix(err.Error(), dir+" lets ") || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Fatalf("a folder BUILTIN\\Users can add entries to must be refused, naming it and the group: %v", err)
	}
}

func TestOpenClawInstallPolicyACLTrustedWindows(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	current := user.User.Sid.String()
	cases := []struct {
		name, sddl string
		ok         bool
	}{
		{"default system drive root", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x4;;;BU)(A;CIIO;0x2;;;BU)(A;OICIIO;GA;;;CO)", false},
		{"profile folder", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + current + ")", true},
		{"read and execute for everyone", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;WD)(A;OICI;0x1200a9;;;BU)", true},
		{"a deny is skipped", "D:PAI(D;;FA;;;BU)(A;OICI;FA;;;SY)", true},
		// OpenClaw's native reader does not trust TrustedInstaller.
		{"trusted installer write", "D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;FA;;;SY)", false},
		{"authenticated users modify", "D:(A;OICI;0x1301bf;;;AU)", false},
		// Inherit-only ACEs do not apply to the folder (OpenClaw 2026.11.x).
		{"inherit-only creator owner", "D:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)", true},
		{"inherit-only users write", "D:(A;CIIO;0x2;;;BU)(A;OICI;FA;;;SY)", true},
		{"hardened drive root", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CIIO;0x2;;;BU)(A;OICIIO;GA;;;CO)", true},
		{"owner rights write", "D:(A;;0x2;;;OW)", false},
	}
	// OpenClaw 2026.8.35 counts inherit-only ACEs.
	for _, sddl := range []string{"D:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CIIO;0x2;;;BU)(A;OICIIO;GA;;;CO)"} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := openClawInstallPolicyACLTrusted(`C:\x`, sd, current, true); err == nil {
			t.Errorf("%s: counting inherit-only ACEs must refuse", sddl)
		}
	}
	for _, tc := range cases {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		err = openClawInstallPolicyACLTrusted(`C:\x`, sd, current, false)
		if (err == nil) != tc.ok {
			t.Errorf("%s: trusted=%v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
	}
	nullDACL, err := windows.SecurityDescriptorFromString("D:NO_ACCESS_CONTROL")
	if err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyACLTrusted(`C:\x`, nullDACL, current, false); err == nil {
		t.Error("a NULL DACL lets everyone write and must be refused")
	}
}

// The owner may rewrite the DACL: an owner outside the trust set is refused
// unless an OWNER RIGHTS ACE takes away its implicit WRITE_DAC.
func TestOpenClawInstallPolicyOwnerTrustedWindows(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	current := user.User.Sid.String()
	const ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, tc := range []struct {
		name, sddl string
		ok         bool
	}{
		{"owned by the user", "O:" + current + "D:(A;OICI;FA;;;SY)", true},
		{"owned by TrustedInstaller (the C:\\ default)", "O:" + ti + "D:(A;OICI;FA;;;SY)", true},
		{"owned by Administrators", "O:BAD:(A;OICI;FA;;;SY)", true},
		{"owned by Users", "O:BUD:(A;OICI;FA;;;SY)", false},
		{"owned by Users, OWNER RIGHTS read only", "O:BUD:(A;;0x1200a9;;;OW)(A;OICI;FA;;;SY)", true},
		{"owned by Users, inherit-only OWNER RIGHTS", "O:BUD:(A;OICIIO;0x1200a9;;;OW)(A;OICI;FA;;;SY)", false},
		{"no owner", "D:(A;OICI;FA;;;SY)", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if err := openClawInstallPolicyOwnerTrusted(`C:\x`, sd, current); (err == nil) != tc.ok {
			t.Errorf("%s: trusted=%v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
	}
}

// GAP-1139, GAP-1170: setup registers the install policy below a drive root
// hardened to drop BUILTIN\Users:(CI)(AD) only for an OpenClaw that skips
// inherit-only ACEs (2026.11.3 and later); for 2026.8.35 it says the release
// is too old, below the default root it names the entry, and an untrusted
// owner is refused. applyOpenClawInstallPolicy runs directly, so no bundle
// is needed and the test cannot skip.
func TestOpenClawInstallPolicyRegisteredBelowAHardenedRootWindows(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	command := filepath.Join(t.TempDir(), "bin", "defenseclaw-gateway.exe")
	if err := os.MkdirAll(filepath.Dir(command), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(command, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevExe, prevTrust, prevOut, prevRead := openClawInstallPolicyExecutable, openClawInstallPolicyTrusted, openClawTeardownNoticeOutput, openClawInstallPolicyReadSecurity
	openClawInstallPolicyExecutable = func() (string, error) { return command, nil }
	openClawInstallPolicyTrusted = openClawInstallPolicyPathTrusted
	openClawTeardownNoticeOutput = io.Discard
	t.Cleanup(func() {
		openClawInstallPolicyExecutable, openClawInstallPolicyTrusted, openClawTeardownNoticeOutput = prevExe, prevTrust, prevOut
		openClawInstallPolicyReadSecurity = prevRead
	})
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	const ti = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	own := "O:" + me + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")"
	const hardened = ti + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CIIO;0x2;;;BU)(A;OICIIO;GA;;;CO)"
	const defaultRoot = ti + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x4;;;BU)(A;CIIO;0x2;;;BU)(A;OICIIO;GA;;;CO)"
	for _, tc := range []struct {
		name, version, root, folder, want string
	}{
		{"11.3 hardened root", "2026.11.3", hardened, own, "registered"},
		{"11.5 hardened root", "OpenClaw 2026.11.5 (abc1234)", hardened, own, "registered"},
		{"11.3 default root", "2026.11.3", defaultRoot, own, "not registered: OpenClaw would refuse"},
		{"8.35 hardened root", "2026.8.35", hardened, own, "not registered: OpenClaw 2026.8.35 is too old for strict install policy on Windows (needs 2026.11.3 or later)"},
		{"8.35 default root", "2026.8.35", defaultRoot, own, "not registered: OpenClaw would refuse"},
		{"11.3 folder owned by Users", "2026.11.3", hardened, "O:BUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;" + me + ")", "not registered: DefenseClaw does not register"},
	} {
		root, folder := tc.root, tc.folder
		openClawInstallPolicyReadSecurity = func(p string) (*windows.SECURITY_DESCRIPTOR, error) {
			switch {
			case filepath.Dir(p) == p:
				return windows.SecurityDescriptorFromString(root)
			case p == filepath.Dir(command):
				return windows.SecurityDescriptorFromString(folder)
			}
			return windows.SecurityDescriptorFromString(own)
		}
		if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		discardOpenClawInstallPolicyRecord(dir)
		opts := SetupOpts{DataDir: dir, AgentVersion: tc.version, OpenClawInstallPolicy: true, OpenClawInstallPolicyTimeoutMs: 45000}
		state, err := applyOpenClawInstallPolicy(configPath, opts)
		if err != nil || !strings.HasPrefix(state, tc.want) {
			t.Fatalf("%s: state = %q, err = %v; want prefix %q", tc.name, state, err, tc.want)
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if registered := strings.Contains(string(data), "installPolicy"); registered != (tc.want == "registered") {
			t.Fatalf("%s: openclaw.json has installPolicy=%v, state %q", tc.name, registered, state)
		}
		saved, err := os.ReadFile(openClawInstallPolicyStatePath(dir))
		if err != nil || !strings.Contains(string(saved), `"state": "`+tc.want[:10]) {
			t.Fatalf("%s: state file = %s (%v)", tc.name, saved, err)
		}
	}
}
