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

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const privatePluginTestSID = "S-1-5-21-1111111111-2222222222-3333333333-1017"

func TestWindowsPrivatePluginDescriptorShape(t *testing.T) {
	target, err := windows.StringToSid(privatePluginTestSID)
	if err != nil {
		t.Fatal(err)
	}
	const sid = privatePluginTestSID
	cases := []struct {
		name string
		sddl string
		want string
	}{
		{"managed", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;BA)", windowsPluginShapeManaged},
		{"managed in another order", "D:P(A;;FR;;;BA)(A;;FA;;;" + sid + ")(A;;FA;;;SY)", windowsPluginShapeManaged},
		{"connector publication", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")", windowsPluginShapePublished},
		{"older guardian footprint", "D:P(A;;RC;;;OW)(A;;0x1301bf;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)", windowsPluginShapeGuardian},
		{"administrators full control", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FA;;;BA)", windowsPluginShapeGuardian},
		{"administrators read twice", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;BA)(A;;FR;;;BA)", windowsPluginShapeGuardian},
		{"target restricted its own access", "D:P(A;;FA;;;SY)(A;;FR;;;" + sid + ")(A;;FR;;;BA)", windowsPluginShapeGuardian},
		{"everyone added", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;BA)(A;;FR;;;WD)", windowsPluginShapeForeign},
		{"another user added", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;S-1-5-21-1111111111-2222222222-3333333333-1018)", windowsPluginShapeForeign},
		{"unprotected", "D:(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;BA)", windowsPluginShapeForeign},
		{"missing system", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BA)", windowsPluginShapeForeign},
		{"deny entry", "D:P(D;;FW;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;" + sid + ")", windowsPluginShapeForeign},
		{"owner rights write", "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;" + sid + ")", windowsPluginShapeForeign},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := windowsPrivatePluginDescriptorShape(sd, target)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("shape = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWindowsManagedPluginProtectionACLIsTheManagedShape(t *testing.T) {
	target, err := windows.StringToSid(privatePluginTestSID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := windowsManagedPluginProtectionACL(target, true); err == nil {
		t.Fatal("managed plugin DACL was built for a directory")
	}
	if _, err := windowsManagedPluginProtectionACL(nil, false); err == nil {
		t.Fatal("managed plugin DACL was built without a target")
	}
	acl, err := windowsManagedPluginProtectionACL(target, false)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatal(err)
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		t.Fatal(err)
	}
	shape, err := windowsPrivatePluginDescriptorShape(sd, target)
	if err != nil {
		t.Fatal(err)
	}
	if shape != windowsPluginShapeManaged {
		t.Fatalf("managed plugin DACL classifies as %q", shape)
	}
}

func TestWindowsPrivatePluginPathSelectedMatchesCleanAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	plugin := filepath.Join(dir, "plugins", "defenseclaw.ts")
	selected := map[string]bool{}
	abs, err := filepath.Abs(plugin)
	if err != nil {
		t.Fatal(err)
	}
	selected[filepathKey(abs)] = true
	if !windowsPrivatePluginPathSelected(selected, filepath.Join(dir, "plugins", ".", "defenseclaw.ts")) {
		t.Fatal("equivalent plugin path was not selected")
	}
	if windowsPrivatePluginPathSelected(selected, plugin+".lock") {
		t.Fatal("plugin lock file must keep the generic footprint DACL")
	}
	if windowsPrivatePluginPathSelected(nil, plugin) {
		t.Fatal("empty selection matched")
	}
}

// privatePluginFixture is a target-owned profile root, plugin directory and
// plugin file for the current test token. The owner is set explicitly because
// an elevated test token defaults new objects to BUILTIN\Administrators.
type privatePluginFixture struct {
	target *windows.SID
	home   string
	path   string
}

func newPrivatePluginFixture(t *testing.T) privatePluginFixture {
	t.Helper()
	target := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	plugins := filepath.Join(home, ".config", "opencode", "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(plugins, "defenseclaw.js")
	if err := os.WriteFile(path, []byte("// plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, element := range []string{
		home,
		filepath.Join(home, ".config"),
		filepath.Join(home, ".config", "opencode"),
		plugins,
		path,
	} {
		if err := windows.SetNamedSecurityInfo(element, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
			t.Skipf("test token cannot own its fixture (%v); the ownership branch is covered live", err)
		}
	}
	return privatePluginFixture{target: target, home: home, path: path}
}

func setPrivatePluginFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWindowsPrivatePluginFileRequiresManagedShape(t *testing.T) {
	fixture := newPrivatePluginFixture(t)
	target := fixture.target
	dir := filepath.Dir(fixture.path)
	if err := verifyWindowsPrivatePluginFile(filepath.Join(dir, "missing.js"), target, false); err != nil {
		t.Fatalf("optional missing plugin: %v", err)
	}
	if err := verifyWindowsPrivatePluginFile(filepath.Join(dir, "missing.js"), target, true); err == nil {
		t.Fatal("required missing plugin passed")
	}
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")(A;;FR;;;BA)")
	if err := verifyWindowsPrivatePluginFile(fixture.path, target, true); err != nil {
		t.Fatalf("managed plugin rejected: %v", err)
	}
	for _, sddl := range []string{
		"D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")",
		"D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")(A;;FA;;;BA)",
		"D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")(A;;FR;;;BA)(A;;FR;;;WD)",
	} {
		setPrivatePluginFixtureDACL(t, fixture.path, sddl)
		if err := verifyWindowsPrivatePluginFile(fixture.path, target, true); err == nil {
			t.Fatalf("plugin DACL %s passed the managed check", sddl)
		}
	}
	other, err := windows.StringToSid(privatePluginTestSID)
	if err != nil {
		t.Fatal(err)
	}
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")(A;;FR;;;BA)")
	if err := verifyWindowsPrivatePluginFile(fixture.path, other, true); err == nil ||
		!strings.Contains(err.Error(), "not owned by the target user") {
		t.Fatalf("plugin owned by another account: %v", err)
	}
}

// The connector publishes target + LocalSystem; hardening under the target's
// own token completes the managed plugin DACL, which Administrators can read
// and verification accepts.
func TestHardenWindowsPrivatePluginFileCompletesThePublication(t *testing.T) {
	fixture := newPrivatePluginFixture(t)
	target := fixture.target
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")")
	if err := hardenWindowsPrivatePluginFile(fixture.home, fixture.path, target); err != nil {
		t.Fatalf("harden published plugin: %v", err)
	}
	if err := verifyWindowsPrivatePluginFile(fixture.path, target, true); err != nil {
		t.Fatalf("hardened plugin rejected: %v", err)
	}
	// Idempotent on the managed shape.
	if err := hardenWindowsPrivatePluginFile(fixture.home, fixture.path, target); err != nil {
		t.Fatalf("harden managed plugin: %v", err)
	}
	// After setup, a widened DACL is not silently accepted.
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")(A;;FR;;;WD)")
	if err := hardenWindowsPrivatePluginFile(fixture.home, fixture.path, target); err == nil {
		t.Fatal("hardening accepted a plugin another principal can read")
	}
	if err := hardenWindowsPrivatePluginFile(fixture.home, filepath.Join(filepath.Dir(fixture.path), "missing.js"), target); err != nil {
		t.Fatalf("missing optional plugin: %v", err)
	}
}

// Before setup, the LocalSystem relax step gives a target-owned plugin with
// any other DACL the managed plugin DACL; the published and managed shapes
// are left untouched, and a hard-linked plugin is refused.
func TestRestoreWindowsPrivatePluginFileReturnsTheManagedDACL(t *testing.T) {
	fixture := newPrivatePluginFixture(t)
	target := fixture.target
	calls := 0
	original := windowsManagedPluginDACLRepairAsService
	windowsManagedPluginDACLRepairAsService = func(home, path string, sid *windows.SID) error {
		calls++
		// The production helper runs this walker as LocalSystem with
		// backup/restore privileges; the test token owns the fixture.
		return repairWindowsTargetOwnedPathDACLNoFollowWithACL(home, path, sid, false, windowsManagedPluginProtectionACL)
	}
	t.Cleanup(func() { windowsManagedPluginDACLRepairAsService = original })

	for _, sddl := range []string{
		"D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")",
		"D:P(A;;FA;;;SY)(A;;FA;;;" + target.String() + ")(A;;FR;;;BA)",
	} {
		setPrivatePluginFixtureDACL(t, fixture.path, sddl)
		if err := restoreWindowsPrivatePluginFile(fixture.home, fixture.path, target); err != nil {
			t.Fatalf("restore %s: %v", sddl, err)
		}
	}
	if calls != 0 {
		t.Fatalf("published/managed plugin was rewritten %d times", calls)
	}
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")(A;;FA;;;WD)")
	if err := restoreWindowsPrivatePluginFile(fixture.home, fixture.path, target); err != nil {
		t.Fatalf("restore widened plugin: %v", err)
	}
	if calls != 1 {
		t.Fatalf("widened plugin repair calls = %d, want 1", calls)
	}
	if err := verifyWindowsPrivatePluginFile(fixture.path, target, true); err != nil {
		t.Fatalf("restored plugin rejected: %v", err)
	}

	link := fixture.path + ".link"
	if err := os.Link(fixture.path, link); err != nil {
		t.Skipf("hard link fixture unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	setPrivatePluginFixtureDACL(t, fixture.path, "D:P(A;;FA;;;SY)(A;;FA;;;"+target.String()+")(A;;FA;;;WD)")
	if err := restoreWindowsPrivatePluginFile(fixture.home, fixture.path, target); err == nil {
		t.Fatal("hard-linked plugin was restored")
	}
	if calls != 1 {
		t.Fatalf("hard-linked plugin reached the repair (%d calls)", calls)
	}
}
