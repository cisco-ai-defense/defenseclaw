// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1855: since GAP-1798 every S4U failure is the signed-out sentinel, and
// the OpenCode port warning told the administrator to "sign in to that
// account" whatever Windows answered. A deleted or unresolvable account and
// an S4U setup failure (no SeTcbPrivilege) are not fixed by a sign-in: the
// fix now names the cause. A plain refused logon keeps the sign-in fix.
func TestGAP1855SignedOutPortFixNamesTheS4UCause(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		want  string
	}{
		{"deleted account", windows.ERROR_NONE_MAPPED, "cannot resolve this account"},
		{"domain trust lost", windows.ERROR_TRUSTED_RELATIONSHIP_FAILURE, "cannot resolve this account"},
		{"no SeTcbPrivilege (LSA)", windows.STATUS_PRIVILEGE_NOT_HELD, "cannot make an S4U logon"},
		{"no SeTcbPrivilege (Win32)", windows.ERROR_PRIVILEGE_NOT_HELD, "cannot make an S4U logon"},
		{"refused logon", windows.STATUS_NOT_SUPPORTED, "sign in to that account"},
		{"no domain controller", windows.STATUS_NO_LOGON_SERVERS, "sign in to that account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("%w (S4U logon: %w)", enterprisehooks.ErrEnrolledUserSignedOut, tc.cause)
			entry := windowsOpenCodePortUnknownEntry(openCodeSIDFirst, `C:\Users\u\.config\opencode\opencode.json`, err)
			if !strings.Contains(entry.Fix, tc.want) {
				t.Fatalf("fix %q, want it to contain %q", entry.Fix, tc.want)
			}
			if tc.want != "sign in to that account" && strings.HasPrefix(entry.Fix, "sign in") {
				t.Fatalf("fix %q sends the administrator to a sign-in that cannot fix %v", entry.Fix, tc.cause)
			}
			if entry.Reason != err.Error() {
				t.Fatalf("reason %q lost the full error %q", entry.Reason, err)
			}
		})
	}
}
