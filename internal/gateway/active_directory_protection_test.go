// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// adPackConnector composes the active-directory-protection pack over a shipped
// base pack through the product path (guardrail.Compose + protectionPackSource),
// the exact compose a running gateway performs on reload (rel-1-0-10:GAP-0054).
func adPackConnector(t *testing.T, base string) string {
	t.Helper()
	baseDir := filepath.Join("..", "..", "policies", "guardrail", base)
	rp, err := guardrail.LoadRulePack(baseDir)
	if err != nil {
		t.Fatalf("load base %s: %v", base, err)
	}
	composed, err := guardrail.Compose(rp, protectionPackSource,
		guardrail.Customization{Protections: []string{"active-directory-protection"}})
	if err != nil {
		t.Fatalf("compose active-directory-protection over %s: %v", base, err)
	}
	connector := "adpack-" + base
	if err := ApplyConnectorRulePackOverrides(connector, composed); err != nil {
		t.Fatalf("activate: %v", err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connector) })
	return connector
}

// TestActiveDirectoryProtectionProfileBoundaries composes the pack over default
// and strict and checks that each AD attack is blocked and each benign admin
// call is allowed. Hosts, accounts and secrets are placeholders.
func TestActiveDirectoryProtectionProfileBoundaries(t *testing.T) {
	type row struct {
		name    string
		command string
		ruleID  string // expected rule id for an attack; "" for benign
		block   bool
	}
	rows := []row{
		{"kerberoast request", "impacket-GetUserSPNs -request -dc-ip 198.51.100.10 example.com/svc:S3cretP4ss", "credential.directory_ticket_request", true},
		{"asrep roast", "impacket-GetNPUsers -request -dc-ip 198.51.100.10 example.com/ -usersfile users.txt -format hashcat", "credential.directory_ticket_request", true},
		{"ntds ifm export", `ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\ntds" q q`, "credential.windows_ntds_ifm_dump", true},
		{"netexec smb password", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares", "credential.directory_service_credential_use", true},
		{"netexec flag before target", "nxc smb --shares 198.51.100.10 -u svc -p S3cretP4ss", "credential.directory_service_credential_use", true},
		{"netexec joined password", "nxc smb 198.51.100.10 -u svc -pS3cretP4ss", "credential.directory_service_credential_use", true},
		{"netexec kerberos ccache", "nxc smb 198.51.100.10 --use-kcache --shares", "credential.directory_service_credential_use", true},
		{"netexec bloodhound", "nxc ldap 198.51.100.10 -u svc -p S3cretP4ss --bloodhound --collection All", "recon.directory_bulk_collection", true},
		{"netexec wordlist spray", "nxc smb 198.51.100.0/24 -u users.txt -p passwords.txt", "credential.directory_password_spray", true},
		// Benign administration must be allowed with the pack on.
		{"klist", "klist", "", false},
		{"domain join", "net ads join -U administrator", "", false},
		{"single ldapsearch", `ldapsearch -x -H ldap://198.51.100.10 -b dc=example,dc=com "(sAMAccountName=svc)"`, "", false},
		{"netexec no credential", "nxc smb 198.51.100.10 --shares", "", false},
		{"netexec help", "nxc smb 198.51.100.10 -h", "", false},
		{"netexec log file not a spray", "nxc smb 198.51.100.10 -u svc -p S3cretP4ss --log run.txt", "credential.directory_service_credential_use", true}, // blocks, but NOT as spray
	}
	for _, base := range []string{"default", "strict"} {
		connector := adPackConnector(t, base)
		for _, r := range rows {
			t.Run(base+"/"+r.name, func(t *testing.T) {
				input := actionfacts.Input{Tool: "shell", Command: r.command}
				if strings.HasPrefix(r.command, "ntdsutil") || strings.HasPrefix(r.command, "dsquery") {
					input.DialectHint = actionfacts.DialectCMD
					input.CWD = `C:\repo`
				}
				got := EvaluateDeterministicAction(context.Background(), input, r.command, connector, base)
				if r.block {
					if got.Action != "block" {
						t.Fatalf("action=%q rules=%v parse=%q, want block", got.Action, got.RuleIDs, got.ParseStatus)
					}
					if r.ruleID != "" && !slices.Contains(got.RuleIDs, r.ruleID) {
						t.Fatalf("rules=%v, want %s", got.RuleIDs, r.ruleID)
					}
					if r.name == "netexec log file not a spray" && slices.Contains(got.RuleIDs, "credential.directory_password_spray") {
						t.Fatalf("a --log .txt operand was mislabelled password spraying: %v", got.RuleIDs)
					}
				} else if got.Action != "allow" {
					t.Fatalf("benign %q action=%q rules=%v, want allow", r.command, got.Action, got.RuleIDs)
				}
			})
		}
	}
}
