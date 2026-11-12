// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestActiveDirectoryProtectionProfileBoundaries checks the opt-in
// active-directory-protection pack (rel-1-0-10:GAP-0014, GAP-0017). Hosts,
// accounts and secrets are placeholders (RFC 5737 / example.com); only the
// program and argument structure is the test.
func TestActiveDirectoryProtectionProfileBoundaries(t *testing.T) {
	connector := activateUseCaseProfile(t, "active-directory-protection")
	tests := []struct {
		name    string
		command string
		ruleID  string
		want    bool
	}{
		// Kerberos ticket requests for offline cracking.
		{"kerberoast request", "impacket-GetUserSPNs -request -dc-ip 198.51.100.10 example.com/svc:S3cretP4ss", "credential.directory_ticket_request", true},
		{"asrep roast", "impacket-GetNPUsers -request -dc-ip 198.51.100.10 example.com/ -usersfile users.txt -format hashcat", "credential.directory_ticket_request", true},
		// Directory database export (replication of credential data).
		{"ntds ifm export", `ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\ntds" q q`, "credential.windows_ntds_ifm_dump", true},
		// Credential use against a domain service (GAP-0014).
		{"netexec smb password", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", "credential.directory_service_credential_use", true},
		{"netexec ldap nt hash", "nxc ldap 198.51.100.10 -u svc -H 00112233445566778899aabbccddeeff", "credential.directory_service_credential_use", true},
		{"crackmapexec mssql password", "crackmapexec mssql 198.51.100.10 -u svc --password S3cretP4ss", "credential.directory_service_credential_use", true},
		// Bulk directory collection for attack-path mapping.
		{"netexec bloodhound", "nxc ldap 198.51.100.10 -u svc -p S3cretP4ss --bloodhound --collection All", "recon.directory_bulk_collection", true},
		// Password spraying with a wordlist.
		{"netexec wordlist spray", "nxc smb 198.51.100.0/24 -u users.txt -p passwords.txt", "credential.directory_password_spray", true},
		// Benign administration stays allowed.
		{"klist", "klist", "credential.directory_ticket_request", false},
		{"domain join", "net ads join -U administrator", "credential.directory_service_credential_use", false},
		{"netexec no credential", "nxc smb 198.51.100.10 --shares", "credential.directory_service_credential_use", false},
		{"netexec help", "nxc smb 198.51.100.10 -h", "credential.directory_service_credential_use", false},
		{"dynamic password", "nxc smb 198.51.100.10 -u svc -p $PASS", "credential.directory_service_credential_use", false},
		{"quoted example", `printf '%s\n' "nxc smb 198.51.100.10 -u svc -p S3cretP4ss"`, "credential.directory_service_credential_use", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: test.command}
			if strings.HasPrefix(test.command, "ntdsutil") {
				input.DialectHint = actionfacts.DialectCMD
				input.CWD = `C:\repo`
			}
			got := EvaluateDeterministicAction(
				context.Background(),
				input,
				test.command,
				connector,
				"default",
			)
			matched := slices.Contains(got.RuleIDs, test.ruleID)
			if matched != test.want {
				t.Fatalf("rules=%v action=%q route=%q parse=%q, want %s match=%t",
					got.RuleIDs, got.Action, got.Route, got.ParseStatus, test.ruleID, test.want)
			}
			if test.want && got.Action != "block" {
				t.Fatalf("action=%q findings=%+v, want block", got.Action, got.Findings)
			}
		})
	}
}
