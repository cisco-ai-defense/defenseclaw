//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-0925: a trust refusal names well-known accounts next to their SIDs,
// puts the access mask in words and gives the icacls command that clears
// it.
func TestWindowsEnterpriseNamePrincipals(t *testing.T) {
	original := windowsPrincipalName
	t.Cleanup(func() { windowsPrincipalName = original })
	windowsPrincipalName = func(sid string) string {
		return map[string]string{"S-1-5-32-545": `BUILTIN\Users`, "S-1-3-0": "CREATOR OWNER", "S-1-5-21-1-2-3-1116": `HOST\dcw-ew3b2`}[sid]
	}
	for _, tc := range []struct{ in, want string }{
		{`C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml: untrusted Windows principal S-1-5-32-545 has write-like access mask 0x1301bf`,
			`BUILTIN\Users (S-1-5-32-545) has write access (modify (0x1301bf))`},
		{`untrusted principal S-1-3-0 has write-like access to managed path: C:\Program Files\Cisco\DefenseClaw`,
			`CREATOR OWNER (S-1-3-0) has write access to C:\Program Files\Cisco\DefenseClaw, which only SYSTEM, Administrators and TrustedInstaller may change. Fix: icacls "C:\Program Files\Cisco\DefenseClaw" /remove:g *S-1-3-0`},
		{`copilot: C:\ProgramData\GitHub\Copilot\policy.d: owner S-1-5-21-1-2-3-1116 is not trusted for machine policy directory; expected Administrators, LocalSystem, or TrustedInstaller`,
			`owner HOST\dcw-ew3b2 (S-1-5-21-1-2-3-1116) is not trusted for machine policy directory; expected Administrators, LocalSystem, or TrustedInstaller. Fix: icacls "C:\ProgramData\GitHub\Copilot\policy.d" /setowner *S-1-5-32-544`},
	} {
		if got := windowsEnterpriseNamePrincipals(tc.in); !strings.Contains(got, tc.want) {
			t.Errorf("%s\n got %s\nwant %s", tc.in, got, tc.want)
		}
	}
}
