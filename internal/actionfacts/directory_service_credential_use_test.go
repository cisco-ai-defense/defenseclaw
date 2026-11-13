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
