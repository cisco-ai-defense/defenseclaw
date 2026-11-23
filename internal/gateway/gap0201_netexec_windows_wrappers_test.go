// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10 GAP-0201: credentialed NetExec behind a Windows wrapper (cmd /c,
// powershell -c, Start-Process -FilePath/-ArgumentList, --% stop-parsing) had
// no finding in any profile, while the bare call typed at the same prompt is
// the built-in credential.directory_ticket_request (alert in default and
// permissive, block in strict) and, with the active-directory-protection
// pack, credential.directory_service_credential_use (block on every base).
// The wrapped call is now read as the argv the wrapper hands NetExec and
// takes the same classifier. The benign twins (no credential, help) stay
// allowed with and without the pack.
func TestGAP0201CredentialedNetExecBehindWindowsWrappers(t *testing.T) {
	const call = "smb 198.51.100.10 -u svc -p S3cretP4ss --shares"
	ps, cmd := actionfacts.DialectPowerShell, actionfacts.DialectCMD
	attacks := []struct {
		name, command string
		dialect       actionfacts.Dialect
	}{
		{"ps cmd /c", "cmd /c nxc " + call, ps},
		{"ps cmd /d /c quoted", `cmd /d /c "nxc ` + call + `"`, ps},
		{"cmd cmd /c", "cmd /c nxc " + call, cmd},
		{"ps powershell -c", `powershell -c "nxc ` + call + `"`, ps},
		{"ps pwsh -NoProfile -Command", `pwsh -NoProfile -Command "nxc.exe ` + call + `"`, ps},
		{"cmd powershell -c", `powershell -c "nxc ` + call + `"`, cmd},
		{"ps Start-Process ArgumentList string", `Start-Process nxc -ArgumentList "` + call + `"`, ps},
		{"ps Start-Process FilePath ArgumentList array", `Start-Process -FilePath nxc.exe -ArgumentList "smb","198.51.100.10","-u","svc","-p","S3cretP4ss"`, ps},
		{"ps stop-parsing", "nxc --% " + call, ps},
	}
	benign := []struct {
		name, command string
		dialect       actionfacts.Dialect
	}{
		{"ps cmd /c help", "cmd /c nxc --help", ps},
		{"cmd cmd /c no credential", "cmd /c nxc smb 198.51.100.10 --shares", cmd},
		{"ps powershell -c no credential", `powershell -c "nxc smb 198.51.100.10 --shares"`, ps},
		{"ps Start-Process help", `Start-Process nxc -ArgumentList "--help"`, ps},
		{"ps stop-parsing help", "nxc --% smb 198.51.100.10 -h", ps},
	}
	for _, base := range []string{"default", "strict", "permissive"} {
		pack := adPackConnector(t, base)
		for _, row := range attacks {
			input := actionfacts.Input{Tool: "shell", Command: row.command, DialectHint: row.dialect, CWD: `C:\repo`}
			t.Run(base+"/builtin/"+row.name, func(t *testing.T) {
				got := EvaluateDeterministicAction(context.Background(), input, row.command, "benchmark-"+base, base)
				if !slices.Contains(got.RuleIDs, "credential.directory_ticket_request") {
					t.Fatalf("%q: action=%q rules=%v parse=%q, want credential.directory_ticket_request", row.command, got.Action, got.RuleIDs, got.ParseStatus)
				}
				if wantBlock := base == "strict"; (got.Action == "block") != wantBlock {
					t.Fatalf("%q: action=%q rules=%v, want block=%v", row.command, got.Action, got.RuleIDs, wantBlock)
				}
			})
			t.Run(base+"/pack/"+row.name, func(t *testing.T) {
				got := EvaluateDeterministicAction(context.Background(), input, row.command, pack, base)
				if got.Action != "block" || !slices.Contains(got.RuleIDs, "credential.directory_service_credential_use") {
					t.Fatalf("%q: action=%q rules=%v parse=%q, want block by credential.directory_service_credential_use",
						row.command, got.Action, got.RuleIDs, got.ParseStatus)
				}
			})
		}
		for _, row := range benign {
			input := actionfacts.Input{Tool: "shell", Command: row.command, DialectHint: row.dialect, CWD: `C:\repo`}
			for _, connector := range []string{"benchmark-" + base, pack} {
				t.Run(base+"/benign/"+connector+"/"+row.name, func(t *testing.T) {
					got := EvaluateDeterministicAction(context.Background(), input, row.command, connector, base)
					if got.Action != "allow" {
						t.Fatalf("benign %q: action=%q rules=%v, want allow", row.command, got.Action, got.RuleIDs)
					}
				})
			}
		}
	}
}
