// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func adpBashInput(command string) Input {
	b, _ := json.Marshal(map[string]string{"command": command})
	return Input{Tool: "bash", Args: b}
}

// TestExactNetExecDomainServiceAuth covers the NetExec/CrackMapExec credential
// recognizer that fixes rel-1-0-10:GAP-0014 and GAP-0051. Values are
// placeholders (RFC 5737 documentation addresses, a dummy account and secret);
// only the program and argument structure are the test.
func TestExactNetExecDomainServiceAuth(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		want     bool
		complete bool
	}{
		{"smb password", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", true, true},
		{"ldap nt hash", "nxc ldap 198.51.100.10 -u svc -H 00112233445566778899aabbccddeeff", true, true},
		{"crackmapexec", "crackmapexec smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"netexec long password flag", "netexec mssql 198.51.100.10 -u svc --password S3cretP4ss", true, true},
		{"joined short password", "nxc smb 198.51.100.10 -u svc -pS3cretP4ss", true, true},
		{"password equals form", "nxc smb 198.51.100.10 -u svc --password=S3cretP4ss", true, true},
		{"flag before target", "nxc smb --shares 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"target after flags", "nxc smb -u svc -p S3cretP4ss --shares 198.51.100.10", true, true},
		{"local-auth lm:nt hash", "nxc smb --local-auth 198.51.100.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:00112233445566778899aabbccddeeff", true, true},
		{"kerberos ccache no password", "nxc smb 198.51.100.10 --use-kcache --shares", true, true},
		{"anonymous empty creds", "nxc ldap 198.51.100.10 -u \"\" -p \"\" --users", true, true},
		{"uppercase protocol", "nxc LDAP 198.51.100.10 -u svc -p S3cretP4ss --bloodhound --collection All", true, true},
		{"wordlist spray", "nxc smb 198.51.100.0/24 -u users.txt -p passwords.txt", true, true},
		{"winrm exec", "nxc winrm 198.51.100.10 -u svc -p S3cretP4ss -x whoami", true, true},
		{"ntds dump form", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --ntds", true, true},
		{"help flag", "nxc smb 198.51.100.10 -h", false, false},
		{"version flag", "nxc smb 198.51.100.10 --version", false, false},
		{"no auth indicator", "nxc smb 198.51.100.10 --shares", false, false},
		{"unknown protocol", "nxc ftpx 198.51.100.10 -u svc -p S3cretP4ss", false, false},
		{"dynamic password keeps parse partial", "nxc smb 198.51.100.10 -u svc -p $PASS", false, false},
		{"not netexec", "klist", false, false},
		// Global options before the protocol (rel-1-0-10:GAP-0051 N5).
		{"global flag before protocol", "nxc --verbose smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"global value options before protocol", "nxc -t 4 --timeout=5 --log run.log smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"unknown option before protocol stays partial", "nxc --frobnicate smb 198.51.100.10 -u svc -p S3cretP4ss", false, false},
		{"global option missing its value", "nxc --timeout", false, false},
		{"joined short global value", "nxc -t4 smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"short global value with equals", "nxc -t=4 smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
		{"double dash before protocol", "nxc --verbose -- smb 198.51.100.10 -u svc -p S3cretP4ss", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(adpBashInput(tc.command))
			if len(facts.Commands) == 0 {
				if tc.want {
					t.Fatalf("no command parsed")
				}
				return
			}
			got := ExactNetExecDomainServiceAuth(facts.Commands[0])
			if got != tc.want {
				t.Fatalf("ExactNetExecDomainServiceAuth=%v want %v (status=%s)", got, tc.want, facts.Parse.Status)
			}
			if tc.want && tc.complete && facts.Parse.Status != StatusComplete {
				t.Fatalf("parse status=%s want complete (a recognized credentialed call must be enforcement-eligible)", facts.Parse.Status)
			}
		})
	}
}

// TestExactNetExecDomainServiceAuthWindows keeps the built-in PowerShell and
// cmd parsers at their 1.0.9 behaviour (s7/ad-pack-revert-builtin): NetExec
// under a Windows shell parses partial and gets no credential-read operation,
// so the Windows hook keeps the default reading of the call.
func TestExactNetExecDomainServiceAuthWindows(t *testing.T) {
	cases := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{"powershell nxc", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", DialectPowerShell, false},
		{"cmd nxc", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", DialectCMD, false},
		{"cmd nxc.exe", "nxc.exe smb 198.51.100.10 -u svc -p S3cretP4ss", DialectCMD, false},
		{"powershell netexec.exe hash", "netexec.exe ldap 198.51.100.10 -u svc -H 00112233445566778899aabbccddeeff --users", DialectPowerShell, false},
		{"cmd path-qualified nxc.exe", `C:\Tools\nxc.exe smb 198.51.100.10 -u svc -p S3cretP4ss`, DialectCMD, false},
		{"powershell call operator path", `& 'C:\Users\alice\.local\bin\nxc.exe' smb 198.51.100.10 -u svc -p S3cretP4ss`, DialectPowerShell, false},
		{"powershell global option", "nxc --verbose smb 198.51.100.10 -u svc -p S3cretP4ss", DialectPowerShell, false},
		{"powershell dynamic password", "nxc smb 198.51.100.10 -u svc -p $env:P", DialectPowerShell, false},
		{"cmd dynamic password", "nxc smb 198.51.100.10 -u svc -p %P%", DialectCMD, false},
		{"cmd help", "nxc.exe smb 198.51.100.10 -h", DialectCMD, false},
		{"powershell no credential", "nxc smb 198.51.100.10 --shares", DialectPowerShell, false},
		{"cmd path-qualified no credential", `C:\Tools\nxc.exe smb 198.51.100.10 --shares`, DialectCMD, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command, DialectHint: tc.dialect, CWD: `C:\repo`})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands=%d, want 1", len(facts.Commands))
			}
			command := facts.Commands[0]
			got := ExactNetExecDomainServiceAuth(command) && hasFactOperation(command, OperationCredentialRead)
			if got != tc.want {
				t.Fatalf("recognized=%v want %v (program=%q status=%s ops=%v)",
					got, tc.want, command.Program, facts.Parse.Status, command.Operations)
			}
			if tc.want && facts.Parse.Status != StatusComplete {
				t.Fatalf("parse status=%s want complete", facts.Parse.Status)
			}
			if !tc.want && facts.Parse.Status == StatusComplete {
				t.Fatalf("parse became complete for an unrecognized NetExec call: ops=%v", command.Operations)
			}
		})
	}
}

// TestNetExecNTDSDumpAfterGlobalOptions keeps the NTDS dump owned by the dump
// grammar when a global option precedes the protocol.
func TestNetExecNTDSDumpAfterGlobalOptions(t *testing.T) {
	for _, command := range []string{
		"nxc smb 198.51.100.10 -u administrator -H aa:bb --ntds",
		"nxc smb 198.51.100.10 -u administrator -p S3cretP4ss -M ntdsutil",
	} {
		facts := Analyze(adpBashInput(command))
		if len(facts.Commands) != 1 || !ExactNetExecNTDSDump(facts.Commands[0]) {
			t.Fatalf("command=%q is not an ExactNetExecNTDSDump", command)
		}
	}
	if facts := Analyze(adpBashInput("nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares")); ExactNetExecNTDSDump(facts.Commands[0]) {
		t.Fatal("a credentialed --shares call was taken for an NTDS dump")
	}
	for _, in := range []Input{
		adpBashInput("nxc --verbose smb 198.51.100.10 -u administrator -H aa:bb --ntds"),
	} {
		facts := Analyze(in)
		if !ExactDirectoryCredentialCompromise(facts) {
			t.Fatalf("input=%+v is not a proven NTDS dump (status=%s)", in, facts.Parse.Status)
		}
	}
}
