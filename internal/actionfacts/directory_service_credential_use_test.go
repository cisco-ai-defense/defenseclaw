// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
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

// TestExactNetExecDomainServiceAuthWindows runs the same recognizer on the argv
// from the PowerShell and cmd parsers (rel-1-0-10:GAP-0051 N2): bare nxc,
// nxc.exe and a path-qualified binary are recognized and keep the parse
// complete; a dynamic credential, a help call and a non-credentialed call stay
// partial. A literal double quote in an argument changes nothing: the proof
// reads the call as written, whatever Windows PowerShell 5.1 does to the argv.
func TestExactNetExecDomainServiceAuthWindows(t *testing.T) {
	cases := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{"powershell nxc", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", DialectPowerShell, true},
		{"cmd nxc", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", DialectCMD, true},
		{"cmd nxc.exe", "nxc.exe smb 198.51.100.10 -u svc -p S3cretP4ss", DialectCMD, true},
		{"powershell netexec.exe hash", "netexec.exe ldap 198.51.100.10 -u svc -H 00112233445566778899aabbccddeeff --users", DialectPowerShell, true},
		{"cmd path-qualified nxc.exe", `C:\Tools\nxc.exe smb 198.51.100.10 -u svc -p S3cretP4ss`, DialectCMD, true},
		{"powershell call operator path", `& 'C:\Users\alice\.local\bin\nxc.exe' smb 198.51.100.10 -u svc -p S3cretP4ss`, DialectPowerShell, true},
		{"powershell global option", "nxc --verbose smb 198.51.100.10 -u svc -p S3cretP4ss", DialectPowerShell, true},
		{"powershell dynamic password", "nxc smb 198.51.100.10 -u svc -p $env:P", DialectPowerShell, false},
		{"cmd dynamic password", "nxc smb 198.51.100.10 -u svc -p %P%", DialectCMD, false},
		{"cmd help", "nxc.exe smb 198.51.100.10 -h", DialectCMD, false},
		{"powershell no credential", "nxc smb 198.51.100.10 --shares", DialectPowerShell, false},
		{"cmd path-qualified no credential", `C:\Tools\nxc.exe smb 198.51.100.10 --shares`, DialectCMD, false},
		{"powershell literal double quote in -x", `nxc smb 198.51.100.10 -u svc -p S3cretP4ss -x 'whoami "/all"'`, DialectPowerShell, true},
		{"powershell literal double quote in password", `nxc smb 198.51.100.10 -u svc -p 'S3cret"P4ss'`, DialectPowerShell, true},
		{"cmd upper-case exe", "NXC.EXE smb 198.51.100.10 -u svc -p S3cretP4ss", DialectCMD, true},
		{"powershell cmd launcher", "nxc.cmd smb 198.51.100.10 -u svc -p S3cretP4ss", DialectPowerShell, true},
	}
	// The PowerShell invocation forms and the cme alias of rel-1-0-10:GAP-0406,
	// each the first row with its program word replaced.
	rest, ok := strings.CutPrefix(cases[0].command, "nxc ")
	if !ok || cases[0].dialect != DialectPowerShell || !cases[0].want {
		t.Fatalf("the first row is no longer a recognized PowerShell nxc call")
	}
	for _, form := range []struct {
		name, program string
		want          bool
	}{
		{"powershell unquoted call operator", "& nxc", true},
		{"powershell call operator without a space", "&nxc.exe", true},
		{"powershell unquoted call operator path", `& C:\Tools\nxc.exe`, true},
		{"powershell dot-sourced path", `. C:\Tools\nxc.exe`, true},
		{"powershell cme alias", "cme.exe", true},
		{"powershell bare cme alias", "cme", true},
		{"powershell call operator on another program", "& whoami", false},
		{"powershell call operator on a variable", "& $nxc", false},
	} {
		cases = append(cases, struct {
			name    string
			command string
			dialect Dialect
			want    bool
		}{form.name, form.program + " " + rest, DialectPowerShell, form.want})
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
// grammar when a global option precedes the protocol, in POSIX and cmd.
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
		{Tool: "shell", Command: "nxc.exe smb 198.51.100.10 -u administrator -H aa:bb --ntds", DialectHint: DialectCMD, CWD: `C:\repo`},
	} {
		facts := Analyze(in)
		if !ExactDirectoryCredentialCompromise(facts) {
			t.Fatalf("input=%+v is not a proven NTDS dump (status=%s)", in, facts.Parse.Status)
		}
	}
}

// TestNetExecProgramFamily is the one identity of a NetExec executable word in
// every dialect (rel-1-0-10:GAP-0366): base name, either slash, any case, one
// launcher extension. Near misses stay outside the family.
func TestNetExecProgramFamily(t *testing.T) {
	for word, want := range map[string]string{
		"nxc": "nxc", "NXC": "nxc", "nxc.exe": "nxc", "Nxc.EXE": "nxc", "nxc.cmd": "nxc", "nxc.bat": "nxc",
		"nxc.ps1": "nxc", "netexec": "netexec", "NetExec.exe": "netexec", "crackmapexec": "crackmapexec",
		`C:\Tools\nxc.exe`: "nxc", `c:/tools/NXC.EXE`: "nxc", "/home/u/.local/bin/nxc": "nxc",
		"./nxc": "nxc", `..\bin\netexec.cmd`: "netexec",
		"cme": "crackmapexec", "CME.EXE": "crackmapexec", `C:\Tools\cme.cmd`: "crackmapexec",
	} {
		if got, ok := netExecProgramFamily(word); !ok || got != want {
			t.Errorf("netExecProgramFamily(%q) = %q, %v; want %q", word, got, ok, want)
		}
	}
	for _, word := range []string{
		"", " nxc", "nxc ", "nxc.exe.exe", "nxc.txt", "nxcc", "xnxc", "nxc.exe/", "john", "cmd.exe", `C:\Tools\nxc.exe\`, ".",
	} {
		if got, ok := netExecProgramFamily(word); ok {
			t.Errorf("netExecProgramFamily(%q) = %q; want no family", word, got)
		}
	}
}
