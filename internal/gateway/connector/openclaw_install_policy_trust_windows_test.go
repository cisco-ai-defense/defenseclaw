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
	// BUILTIN\Users may create folders in dir, as on a drive root.
	sd, err := windows.SecurityDescriptorFromString("D:(A;CI;0x4;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")
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
	err = openClawInstallPolicyPathTrusted(command, "")
	if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "S-1-5-32-545") {
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
		{"trusted installer and a deny", "D:PAI(D;;FA;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)", true},
		{"authenticated users modify", "D:(A;OICI;0x1301bf;;;AU)", false},
		{"inherit-only creator owner", "D:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)", false},
		{"owner rights write", "D:(A;;0x2;;;OW)", false},
	}
	for _, tc := range cases {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		err = openClawInstallPolicyACLTrusted(`C:\x`, sd, current)
		if (err == nil) != tc.ok {
			t.Errorf("%s: trusted=%v, want %v (%v)", tc.name, err == nil, tc.ok, err)
		}
	}
	nullDACL, err := windows.SecurityDescriptorFromString("D:NO_ACCESS_CONTROL")
	if err != nil {
		t.Fatal(err)
	}
	if err := openClawInstallPolicyACLTrusted(`C:\x`, nullDACL, current); err == nil {
		t.Error("a NULL DACL lets everyone write and must be refused")
	}
}
