//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// GAP-0925: the relaxed-ancestor advisory status, verify and policy show
// print names the account, the mask in words and the icacls fix on a
// standalone install; elsewhere it is left as it was.
func TestWindowsStandaloneTrustAdvisoryNamesTheAccountAndTheFix(t *testing.T) {
	originalName, originalStandalone := windowsPrincipalName, managedHostWindowsStandalone
	t.Cleanup(func() { windowsPrincipalName, managedHostWindowsStandalone = originalName, originalStandalone })
	windowsPrincipalName = func(sid string) string {
		return map[string]string{"S-1-5-32-545": `BUILTIN\Users`}[sid]
	}
	raw := `C:\ProgramData\Cisco\DefenseClaw\etc: untrusted Windows principal S-1-5-32-545 has write-like access mask 0x1301bf`
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
	got := managed.DescribeTrustAdvisoryReason(raw)
	for _, want := range []string{`BUILTIN\Users (S-1-5-32-545) has write access (modify (0x1301bf))`, `Fix: icacls "C:\ProgramData\Cisco\DefenseClaw\etc" /remove:g *S-1-5-32-545`} {
		if !strings.Contains(got, want) {
			t.Errorf("advisory reason %q lacks %q", got, want)
		}
	}
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if got := managed.DescribeTrustAdvisoryReason(raw); got != raw {
		t.Errorf("non-standalone advisory reason was rewritten: %q", got)
	}
}

// GAP-1061: the verify message for an untrusted targets.yaml leads with the
// account and the icacls fix, and never tells the administrator to wait.
func TestVerifyNamesTheUntrustedManifestAccountFirst(t *testing.T) {
	previous := windowsPrincipalName
	t.Cleanup(func() { windowsPrincipalName = previous })
	windowsPrincipalName = func(sid string) string { return `HOST\dcg` }
	in := `untrusted principal S-1-5-21-1-2-3-1001 has write-like access to managed path: C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml`
	got := windowsEnterpriseNamePrincipals(in)
	if !strings.HasPrefix(got, `HOST\dcg (S-1-5-21-1-2-3-1001) has write access to C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml`) ||
		!strings.Contains(got, `Fix: icacls "C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml" /remove:g *S-1-5-21-1-2-3-1001`) ||
		strings.Contains(got, "guardian's next pass") {
		t.Fatalf("message = %q", got)
	}
}

// Review D3: the fix for a write-like entry on a vendor folder replaces the
// stock reader group's entry by read and execute; /remove:g would take the
// vendor's read entry away too. DefenseClaw's own folders, other accounts and
// an account with no read keep /remove:g.
func TestWindowsWriterFixKeepsTheReadOfTheStockReaderGroups(t *testing.T) {
	originalReads, originalDirectory := managed.StandalonePrincipalReadsPath, managed.StandalonePathIsDirectory
	t.Cleanup(func() {
		managed.StandalonePrincipalReadsPath, managed.StandalonePathIsDirectory = originalReads, originalDirectory
	})
	reads, directory := true, true
	managed.StandalonePrincipalReadsPath = func(string, string) bool { return reads }
	managed.StandalonePathIsDirectory = func(string) bool { return directory }
	vendor := `C:\ProgramData\OpenAI`
	for _, tc := range []struct {
		name, path, sid, want string
		reads, directory      bool
	}{
		{"Users on a vendor folder", vendor, "S-1-5-32-545", `icacls "C:\ProgramData\OpenAI" /remove:g *S-1-5-32-545 /grant "*S-1-5-32-545:(OI)(CI)(RX)"`, true, true},
		{"Authenticated Users on a vendor folder", vendor, "S-1-5-11", `/remove:g *S-1-5-11 /grant "*S-1-5-11:(OI)(CI)(RX)"`, true, true},
		{"Everyone on a vendor folder", vendor, "S-1-1-0", `/remove:g *S-1-1-0 /grant "*S-1-1-0:(OI)(CI)(RX)"`, true, true},
		{"Users on a vendor file", vendor + `\requirements.toml`, "S-1-5-32-545", `/remove:g *S-1-5-32-545 /grant "*S-1-5-32-545:(RX)"`, true, false},
		{"Users with no read there", vendor, "S-1-5-32-545", `icacls "C:\ProgramData\OpenAI" /remove:g *S-1-5-32-545`, false, true},
		{"another account", vendor, "S-1-5-21-1-2-3-1001", `icacls "C:\ProgramData\OpenAI" /remove:g *S-1-5-21-1-2-3-1001`, true, true},
		{"Users on DefenseClaw's own folder", `C:\ProgramData\Cisco\DefenseClaw\etc`, "S-1-5-32-545", `icacls "C:\ProgramData\Cisco\DefenseClaw\etc" /remove:g *S-1-5-32-545`, true, true},
	} {
		reads, directory = tc.reads, tc.directory
		if got := windowsWriterFix(tc.path, tc.sid); got != tc.want && !strings.Contains(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// The rewritten verdict carries it: the read is granted again in the same command.
	reads, directory = true, true
	got := windowsEnterpriseNamePrincipals(vendor + `: untrusted Windows principal S-1-5-32-545 has write-like access mask 0x1301bf`)
	if !strings.Contains(got, `Fix: icacls "C:\ProgramData\OpenAI" /remove:g *S-1-5-32-545 /grant "*S-1-5-32-545:(OI)(CI)(RX)"`) {
		t.Errorf("a verdict on a vendor folder: %q", got)
	}
}
