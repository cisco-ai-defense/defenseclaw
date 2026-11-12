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
// recognizer that fixes rel-1-0-10:GAP-0014. Values are placeholders (RFC 5737
// documentation address, a dummy account and secret); only the program and
// argument structure matter.
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
		{"netexec mssql long password flag", "netexec mssql 198.51.100.10 -u svc --password S3cretP4ss", true, true},
		{"wordlist spray", "nxc smb 198.51.100.0/24 -u users.txt -p passwords.txt", true, true},
		{"bloodhound with creds", "nxc ldap 198.51.100.10 -u svc -p S3cretP4ss --bloodhound --collection All", true, true},
		{"no credential flag", "nxc smb 198.51.100.10 --shares", false, false},
		{"help flag", "nxc smb 198.51.100.10 -h", false, false},
		{"unknown protocol", "nxc ftpx 198.51.100.10 -u svc -p S3cretP4ss", false, false},
		{"dynamic password", "nxc smb 198.51.100.10 -u svc -p ${PASS}", false, false},
		{"missing target", "nxc smb -u svc -p S3cretP4ss", false, false},
		{"ntds dump (owned elsewhere, still recognized complete)", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --ntds", true, true},
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
				t.Fatalf("parse status=%s want complete (recognized credentialed call must be enforcement-eligible)", facts.Parse.Status)
			}
		})
	}
}
