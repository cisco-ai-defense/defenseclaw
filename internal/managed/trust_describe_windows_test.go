//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0386: a rule pack is one guardrail profile's policy, and a standard
// user may see only their own. Setup's fix grants read to the gateway
// service account by its SID (it exists before the service does), never
// BUILTIN\Users, and status finds the standard-user groups that can still
// read a pack.
func TestRulePackReadIsForTheGatewayOnly(t *testing.T) {
	const gateway = "*S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274:(OI)(CI)RX"
	if got := RulePackServiceReadGrant(DefaultGatewayServiceAccount); got != gateway {
		t.Fatalf("grant %q, want %q", got, gateway)
	}
	if got := RulePackServiceReadGrant(""); got != gateway {
		t.Fatalf("grant without a pinned account %q, want %q", got, gateway)
	}
	pack := filepath.Join(t.TempDir(), "es-strict")
	refused := &UntrustedPrincipalError{Path: pack, SID: "S-1-5-11", text: "x"}
	text, ok := DescribeUntrustedRulePack("guardrail.custom_packs.es-strict.path", pack, DefaultGatewayServiceAccount, refused)
	if !ok || strings.Contains(text, "S-1-5-32-545") || !strings.Contains(text, `"`+gateway+`"`) {
		t.Fatalf("fix %q, want the gateway grant and no Users grant", text)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	setDACL := func(sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl + "(A;OICI;FA;;;" + user.User.Sid.String() + ")")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;S-1-5-21-1-2-3-513)")
	if readers, err := StandardUserReadersOf(dir); err != nil || !reflect.DeepEqual(readers, []string{"S-1-5-32-545", "S-1-5-21-1-2-3-513"}) {
		t.Fatalf("readers %q (%v), want Users and Domain Users", readers, err)
	}
	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274)")
	if readers, err := StandardUserReadersOf(dir); err != nil || len(readers) != 0 {
		t.Fatalf("readers %q (%v), want none", readers, err)
	}
}
