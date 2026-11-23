// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// gap1827GatewaySID is NT SERVICE\DefenseClawGateway as an SDDL SID.
var gap1827GatewaySID = managed.WindowsServiceSIDString(managed.StandaloneWindowsGatewaySvc)

// gap1827LiveFolderSDDL is the DACL of C:\Users\dcw-std1\.codex on
// dc-ent-win (1.0.11 smoke, 2026-11-22): the guardian setup shape plus the
// gateway read grant the hook enumerator adds (read on the folder, an
// inherit-only generic read and execute for its children).
func gap1827LiveFolderSDDL(service string) string {
	return "D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;" + service + ")(A;;0x1200a9;;;" + service + ")"
}

// gap1827SetFolderDACL gives the fixture folder sddl's protected DACL. It
// does not reach the LocalSystem-owned config inside it: that file's DACL
// grants the elevated test account nothing, and the propagation skips it
// without an error. gap1827InheritFromFolder gives the config its inherited
// entries.
func gap1827SetFolderDACL(t *testing.T, dir, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("set folder DACL %s: %v", sddl, err)
	}
}

// gap1827InheritFromFolder gives path the DACL a file a privileged writer
// creates in its folder gets: no explicit entries, inheritance on, so it holds
// exactly what the folder's DACL passes down. It runs with the repair
// privileges because the LocalSystem-owned config grants the elevated test
// account nothing (GAP-2028: without this the config kept the two entries of
// the bare guardian folder and the test never reached the heal).
func gap1827InheritFromFolder(t *testing.T, path string) {
	t.Helper()
	empty, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		t.Fatal(err)
	}
	emptyDACL, _, err := empty.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := runWindowsManagedPrivilegedRepair(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, emptyDACL, nil)
	}); err != nil {
		t.Fatalf("inherit the folder DACL onto %s: %v", path, err)
	}
}

// gap1827FileDACL is path's DACL as SDDL (D: part only), read as LocalSystem.
func gap1827FileDACL(t *testing.T, path string) string {
	t.Helper()
	var sddl string
	if err := runWindowsManagedPrivilegedRepair(func() error {
		handle, err := openWindowsManagedRepairHandle(path, false, windows.READ_CONTROL)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		sddl = sd.String()
		if i := strings.Index(sddl, "D:"); i > 0 {
			sddl = sddl[i:]
		}
		return nil
	}); err != nil {
		t.Fatalf("read DACL of %s: %v", path, err)
	}
	return sddl
}

// gap1827RequireLiveConfigDACL fails unless sddl is the DACL of the live
// dcw-std1 config.toml on dc-ent-win (1.0.11 smoke, 2026-11-22):
// D:AI(A;ID;0x1200a9;;;<gateway>)(A;ID;FA;;;SY)(A;ID;FA;;;OW), not protected,
// those three inherited entries in any order.
func gap1827RequireLiveConfigDACL(t *testing.T, sddl string) {
	t.Helper()
	open := strings.Index(sddl, "(")
	if !strings.HasPrefix(sddl, "D:") || open < 0 || strings.Contains(sddl[2:open], "P") {
		t.Fatalf("fixture: config DACL %s is protected or empty; the live file inherits D:AI(gateway RX)(SYSTEM)(OWNER RIGHTS)", sddl)
	}
	got := strings.SplitAfter(sddl[open:], ")")
	got = got[:len(got)-1]
	want := []string{"(A;ID;0x1200a9;;;" + gap1827GatewaySID + ")", "(A;ID;FA;;;SY)", "(A;ID;FA;;;OW)"}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "") != strings.Join(want, "") {
		t.Fatalf("fixture: config carries %d ACEs %s; the live file inherits 3 (gateway RX, SYSTEM, OWNER RIGHTS)", len(got), sddl)
	}
}

// TestGAP1827ConfigInAFolderWithTheGatewayReadGrantIsGivenBack replays the
// live dcw-std1 shape: the account's .codex folder carries the guardian
// setup DACL and the enumerator's gateway read grant, and a config.toml a
// privileged writer created there is owned by LocalSystem with the three
// entries it inherited (gateway RX, SYSTEM, OWNER RIGHTS). A route-only
// style edit as the account must heal the owner and succeed. Fails on
// rel/1.0.11 5597ca2b83: the heal accepted only the bare two-entry folder
// and file DACLs, so it never fired and verify stayed 1603.
func TestGAP1827ConfigInAFolderWithTheGatewayReadGrantIsGivenBack(t *testing.T) {
	path, stateDir, user := gap1651Fixture(t, nil)
	gap1827SetFolderDACL(t, filepath.Dir(path), gap1827LiveFolderSDDL(gap1827GatewaySID))
	t.Logf("config DACL after the folder DACL change alone: %s", gap1827FileDACL(t, path))
	gap1827InheritFromFolder(t, path)
	gap1827RequireLiveConfigDACL(t, gap1827FileDACL(t, path))
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can read its LocalSystem-owned config (err %v); the repro needs Access is denied", err)
	}

	err := atomicTransformFileWithStateDir(path, stateDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
		if !exists {
			t.Fatalf("config not seen as existing")
		}
		return atomicTransformResult{Data: append(append([]byte(nil), data...), []byte("[model_providers.dc]\n")...)}, nil
	})
	if err != nil {
		t.Fatalf("GAP-1827: route-only style edit of a LocalSystem-owned config in a gateway-readable guardian folder failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "model = \"gpt\"\n[model_providers.dc]\n" {
		t.Fatalf("config after edit = %q, %v", got, err)
	}
	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.Equals(user) {
		t.Fatalf("GAP-1827: config owner after edit = %v; want the account %s", owner, user)
	}
}

// TestGAP1827ReadGrantsThatAreNotTheGatewaysAreNotHealed: the extra entries
// are accepted only as the gateway's read grant. The same shape for another
// service, or the gateway with more than read, leaves the file alone.
func TestGAP1827ReadGrantsThatAreNotTheGatewaysAreNotHealed(t *testing.T) {
	other := managed.WindowsServiceSIDString("DefenseClawGap1827Other")
	cases := map[string]string{
		"another service": gap1827LiveFolderSDDL(other),
		"gateway write on the folder": "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;" + gap1827GatewaySID +
			")(A;;0x1201bf;;;" + gap1827GatewaySID + ")",
		"gateway full control inherited": "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;" + gap1827GatewaySID +
			")(A;;0x1200a9;;;" + gap1827GatewaySID + ")",
		"gateway grant without its folder entry": "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;" + gap1827GatewaySID + ")",
	}
	for name, sddl := range cases {
		t.Run(name, func(t *testing.T) {
			path, _, _ := gap1651Fixture(t, nil)
			gap1827SetFolderDACL(t, filepath.Dir(path), sddl)
			// The config holds what this folder passes down, so only the
			// folder rule can refuse it.
			gap1827InheritFromFolder(t, path)

			_ = healAtomicTransformV2ConfigLeftToAdmin(path)

			if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
				t.Fatalf("GAP-1827: owner after the heal in folder %s = %v; want LocalSystem kept", sddl, owner)
			}
		})
	}
}

// TestGAP1827SystemOnlyFileRenamedIntoAGatewayReadableFolderStaysSystemOwned
// keeps the GAP-1672 rule on the live folder shape: a SYSTEM-only file the
// account renames into the config slot keeps its protected DACL, so it is
// not a file created in the folder and is not handed over.
func TestGAP1827SystemOnlyFileRenamedIntoAGatewayReadableFolderStaysSystemOwned(t *testing.T) {
	path, _, _ := gap1651Fixture(t, nil)
	gap1827SetFolderDACL(t, filepath.Dir(path), gap1827LiveFolderSDDL(gap1827GatewaySID))
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the fixture config (the account owns the folder): %v", err)
	}
	victim := filepath.Join(t.TempDir(), "machine-secret.toml")
	if err := os.WriteFile(victim, []byte("secret = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;0x1200a9;;;" + gap1827GatewaySID + ")")
	if err != nil {
		t.Fatal(err)
	}
	privateDACL, _, err := private.DACL()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := runWindowsManagedPrivilegedRepair(func() error {
		return windows.SetNamedSecurityInfo(victim, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			system, nil, privateDACL, nil)
	}); err != nil {
		t.Fatalf("make the victim SYSTEM-only: %v", err)
	}
	if err := gap1672RenameWithDeleteOnly(victim, path); err != nil {
		t.Fatalf("rename the SYSTEM-only file into the config slot: %v", err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can read the SYSTEM-only file (err %v); the repro needs Access is denied", err)
	}

	_ = healAtomicTransformV2ConfigLeftToAdmin(path)

	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("GAP-1827: owner of the renamed SYSTEM-only file = %v after the heal; want LocalSystem kept", owner)
	}
}
