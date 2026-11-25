// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestGAP1827RelaxedAgentFolderShapes pins which per-user agent folder and
// config DACLs count as the guardian setup shape, with and without the
// enumerator's gateway read grant. The live strings are from dcw-std1's
// .codex folder and config.toml on dc-ent-win (2026-11-22).
func TestGAP1827RelaxedAgentFolderShapes(t *testing.T) {
	gw := WindowsServiceSIDString(StandaloneWindowsGatewaySvc)
	other := WindowsServiceSIDString("DefenseClawGap1827Other")
	service, err := windows.StringToSid(gw)
	if err != nil {
		t.Fatal(err)
	}
	grant := func(sid string) string { return "(A;OICIIO;GXGR;;;" + sid + ")(A;;0x1200a9;;;" + sid + ")" }
	folders := []struct {
		name                 string
		sddl                 string
		relaxed, serviceRead bool
	}{
		{"bare setup shape", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", true, false},
		{"live .codex with gateway grant", "D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(gw), true, true},
		{"grant for another service", "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(other), false, false},
		{"not protected", "D:(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(gw), false, false},
		{"grant with write on folder", "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;" + gw + ")(A;;0x1201bf;;;" + gw + ")", false, false},
		{"grant twice", "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(gw) + "(A;;0x1200a9;;;" + gw + ")", false, false},
		{"only the inherit-only half", "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICIIO;GXGR;;;" + gw + ")", false, false},
		{"extra users read", "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(gw) + "(A;OICI;0x1200a9;;;BU)", false, false},
		{"deny entry", "D:P(D;;WD;;;WD)(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)", false, false},
	}
	for _, tc := range folders {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		relaxed, serviceRead, err := IsWindowsSetupRelaxedAgentDirectoryDACL(sd, service)
		if err != nil || relaxed != tc.relaxed || serviceRead != tc.serviceRead {
			t.Errorf("%s: relaxed=%v serviceRead=%v err=%v; want %v %v", tc.name, relaxed, serviceRead, err, tc.relaxed, tc.serviceRead)
		}
	}

	files := []struct {
		name        string
		sddl        string
		serviceRead bool
		want        bool
	}{
		{"live config in grant folder", "D:AI(A;ID;0x1200a9;;;" + gw + ")(A;ID;FA;;;SY)(A;ID;FA;;;OW)", true, true},
		{"bare inherited pair in bare folder", "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;OW)", false, true},
		{"bare pair in grant folder", "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;OW)", true, false},
		{"gateway entry in bare folder", "D:AI(A;ID;0x1200a9;;;" + gw + ")(A;ID;FA;;;SY)(A;ID;FA;;;OW)", false, false},
		{"gateway entry explicit", "D:AI(A;;0x1200a9;;;" + gw + ")(A;ID;FA;;;SY)(A;ID;FA;;;OW)", true, false},
		{"another service inherited", "D:AI(A;ID;0x1200a9;;;" + other + ")(A;ID;FA;;;SY)(A;ID;FA;;;OW)", true, false},
		{"protected", "D:PAI(A;ID;0x1200a9;;;" + gw + ")(A;ID;FA;;;SY)(A;ID;FA;;;OW)", true, false},
		{"system-only moved in", "D:P(A;;FA;;;SY)", true, false},
	}
	for _, tc := range files {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, err := IsWindowsSetupRelaxedAgentChildFileDACL(sd, service, tc.serviceRead)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v err %v; want %v", tc.name, got, err, tc.want)
		}
	}

	// The exact two-entry matchers the enterprise hooks use are unchanged.
	bare, _ := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)")
	live, _ := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)" + grant(gw))
	if ok, err := IsWindowsSetupRelaxedDirectoryDACL(bare); err != nil || !ok {
		t.Errorf("IsWindowsSetupRelaxedDirectoryDACL(bare) = %v, %v; want true", ok, err)
	}
	if ok, err := IsWindowsSetupRelaxedDirectoryDACL(live); err != nil || ok {
		t.Errorf("IsWindowsSetupRelaxedDirectoryDACL(with grant) = %v, %v; want false", ok, err)
	}
}
