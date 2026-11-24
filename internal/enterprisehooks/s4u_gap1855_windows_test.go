// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// GAP-1855: an S4U logon for a SID no account maps to fails at the account
// lookup, before any LSA call, and is named as an unresolvable account.
func TestGAP1855S4UOfAnUnmappedSIDIsAnUnresolvedAccount(t *testing.T) {
	sid, err := windows.StringToSid("S-1-5-21-1111111111-2222222222-3333333333-71001")
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveWindowsEnterpriseS4UTargetToken(sid)
	if err == nil {
		t.Fatal("an unmapped SID got an S4U token")
	}
	if !errors.Is(err, ErrS4UAccountUnresolved) {
		t.Fatalf("an unmapped SID is not an unresolved account: %v", err)
	}
	signedOut := &enrolledUserSignedOutError{s4u: err}
	if !errors.Is(signedOut, ErrEnrolledUserSignedOut) {
		t.Fatal("the failure is no longer the signed-out sentinel (GAP-1798 pending rule)")
	}
	if fix := EnrolledUserSignedOutFix(signedOut); !strings.Contains(fix, "cannot resolve this account") {
		t.Fatalf("fix %q", fix)
	}
	if fix := EnrolledUserSignedOutFix(&enrolledUserSignedOutError{s4u: errors.New("logon refused")}); !strings.HasPrefix(fix, "sign in to that account") {
		t.Fatalf("a plain refusal lost the sign-in fix: %q", fix)
	}
	// The repair is named as it runs on a managed computer, not as a bare
	// subcommand (TestManagedWindowsCommandsComeFromTheRenderer).
	repair := managed.WindowsAdminCommand("enterprise", "windows", "repair", "--profile", managed.ProfileStandalone)
	if fix := EnrolledUserSignedOutFix(&enrolledUserSignedOutError{s4u: ErrS4UUnavailable}); !strings.Contains(fix, repair) || !strings.Contains(fix, "elevated PowerShell") {
		t.Fatalf("the S4U-unavailable fix %q does not name %s in an elevated PowerShell prompt", fix, repair)
	}
}
