// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	directoryCredentialAcquisitionRuleID = "credential.directory_credential_acquisition"
	directoryTicketRequestRuleID         = "credential.directory_ticket_request"
)

// The directory credential vocabulary is split by operation class. A dump or an
// offline crack IS the compromise and is owned by
// credential.directory_credential_acquisition at CRITICAL; a bare Kerberos ticket
// request is owned by credential.directory_ticket_request at HIGH, so the returned
// TGS stays observable by credential.returned_kerberos_tgs.
func TestDirectoryCredentialAcquisitionSemanticOwner(t *testing.T) {
	t.Parallel()
	owner := semanticOwners[directoryCredentialAcquisitionRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || owner.alertOnly {
		t.Fatalf("owner posture = %+v", owner)
	}
	input := actionfacts.Input{
		Tool:    "execute_command",
		Command: "impacket-secretsdump -hashes aa:bb corp.example/admin@192.0.2.10",
	}
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) {
		t.Fatalf("exact compromise not owned: %+v", facts)
	}
	raw, err := json.Marshal(map[string]string{"command": input.Command})
	if err != nil {
		t.Fatal(err)
	}
	findings := scanTrustedToolArgs(t, "execute_command", string(raw))
	matched := findingWithID(findings, directoryCredentialAcquisitionRuleID)
	if matched == nil || matched.Severity != "CRITICAL" || matched.Evidence != "" {
		t.Fatalf("semantic finding = %+v; all = %v", matched, FindingStrings(findings))
	}
}

// A bare ticket request must land on the non-enforcing half, at HIGH, and must not
// be claimed by the CRITICAL compromise rule.
func TestDirectoryTicketRequestStaysNonEnforcing(t *testing.T) {
	t.Parallel()
	owner := semanticOwners[directoryTicketRequestRuleID]
	if owner.prerequisite == nil {
		t.Fatalf("ticket-request owner posture = %+v", owner)
	}
	for _, command := range []string{
		"impacket-GetUserSPNs -dc-ip 192.0.2.10 -request corp.example/user",
		"impacket-GetNPUsers corp.example/ -usersfile users.txt -request",
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "execute_command", Command: command})
		if !owner.eligible(facts) {
			t.Fatalf("command=%q ticket request not owned: %+v", command, facts)
		}
		if semanticOwners[directoryCredentialAcquisitionRuleID].eligible(facts) {
			t.Fatalf("command=%q was claimed by the CRITICAL compromise rule", command)
		}
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		findings := scanTrustedToolArgs(t, "execute_command", string(raw))
		matched := findingWithID(findings, directoryTicketRequestRuleID)
		if matched == nil || matched.Severity != "HIGH" {
			t.Fatalf("command=%q ticket finding=%+v all=%v",
				command, matched, FindingStrings(findings))
		}
		if findingWithID(findings, directoryCredentialAcquisitionRuleID) != nil {
			t.Fatalf("command=%q also produced a CRITICAL compromise finding: %v",
				command, FindingStrings(findings))
		}
	}
}

// The two halves must be total and mutually exclusive: an action that mixes a
// request with a crack belongs to the enforcing half, because the crack is present.
func TestDirectoryCredentialSplitIsTotalAndExclusive(t *testing.T) {
	t.Parallel()
	for command, wantCompromise := range map[string]bool{
		"impacket-secretsdump -hashes aa:bb corp.example/admin@192.0.2.10":  true,
		"hashcat -m 13100 tickets.hash wordlist.txt --format=krb5tgs":       true,
		"nxc smb dc.example -u administrator -H aa:bb --ntds":               true,
		"impacket-GetUserSPNs -dc-ip 192.0.2.10 -request corp.example/user": false,
		"impacket-GetNPUsers corp.example/ -usersfile users.txt -request":   false,
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "execute_command", Command: command})
		if !actionfacts.ExactDirectoryCredentialAcquisition(facts) {
			t.Fatalf("command=%q is not a proven acquisition at all: %+v", command, facts)
		}
		gotCompromise := actionfacts.ExactDirectoryCredentialCompromise(facts)
		gotRequest := actionfacts.ExactDirectoryCredentialTicketRequest(facts)
		if gotCompromise != wantCompromise {
			t.Errorf("command=%q compromise=%v, want %v", command, gotCompromise, wantCompromise)
		}
		if gotCompromise == gotRequest {
			t.Errorf("command=%q classified into both or neither half (compromise=%v request=%v)",
				command, gotCompromise, gotRequest)
		}
	}
}

func TestDirectoryCredentialAcquisitionBashLoginWrapperDetectionOnly(t *testing.T) {
	t.Parallel()
	command := `bash -lc 'mkdir -p /tmp/enum && impacket-GetUserSPNs -dc-ip 192.0.2.10 -request corp.example/user; cat /tmp/enum/out'`
	for _, profile := range []string{"default", "permissive", "strict"} {
		evaluation := EvaluateDeterministicAction(
			context.Background(),
			actionfacts.Input{Tool: "execute_command", Command: command},
			command,
			"benchmark-"+profile,
			profile,
		)
		if len(evaluation.Findings) != 1 ||
			evaluation.Findings[0].RuleID != directoryTicketRequestRuleID ||
			evaluation.Findings[0].ContributesToEnforcement ||
			evaluation.Route != "fallback" || evaluation.Authoritative ||
			evaluation.EnforcementEligible || evaluation.Action == guardrailActionBlock ||
			evaluation.Action == guardrailActionConfirm {
			t.Fatalf("profile=%s escaped detection-only boundary: %+v", profile, evaluation)
		}
	}
}

func TestDirectoryCredentialAcquisitionAdditionalExactGrammars(t *testing.T) {
	t.Parallel()
	for _, command := range []string{
		"nxc smb dc.example -u administrator -H aa:bb --ntds",
		"netexec smb dc.example -k --use-kcache -M ntdsutil",
		"john --wordlist=words.txt ticket.hash --format=krb5tgs",
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		findings := scanTrustedToolArgs(t, "execute_command", string(raw))
		matched := findingWithID(findings, directoryCredentialAcquisitionRuleID)
		if matched == nil || matched.Severity != "CRITICAL" || matched.Evidence != "" {
			t.Fatalf("command=%q semantic finding=%+v all=%v", command, matched, FindingStrings(findings))
		}
	}
}

func TestStructuredDirectoryCredentialAcquisitionDetectionOnly(t *testing.T) {
	t.Parallel()
	for tool, arguments := range map[string]string{
		"secretsdump":   `{"method":"dcsync","target":"dc01.example.test","username":"svc"}`,
		"hashcat_crack": `{"attack_mode":"dictionary","hash_file":"tickets.hash","hash_mode":13100}`,
		"kerberoast":    `{"domain":"example.test","target_user":"svc_sql"}`,
	} {
		findings := scanTrustedToolArgs(t, tool, arguments)
		matched := findingWithID(findings, "credential.structured_directory_acquisition")
		if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() {
			t.Fatalf("tool=%s finding=%+v all=%v", tool, matched, FindingStrings(findings))
		}
	}
}

func TestDirectoryCredentialAcquisitionSafeNegatives(t *testing.T) {
	t.Parallel()
	for _, command := range []string{
		"impacket-GetUserSPNs -dc-ip 192.0.2.10 corp.example/user",
		"impacket-GetNPUsers corp.example/ -usersfile users.txt",
		"hashcat -m 0 hashes.txt --show",
		"nxc smb dc.example -u administrator -H aa:bb",
		"nxc smb dc.example -M spider_plus",
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "execute_command", Args: raw})
		owner := semanticOwners[directoryCredentialAcquisitionRuleID]
		if owner.eligible(facts) || owner.suppressFallback == nil || !owner.suppressFallback(facts) {
			t.Fatalf("safe negative %q was not authoritatively suppressed: owner=%+v facts=%+v", command, owner, facts)
		}
		findings := scanTrustedToolArgs(t, "execute_command", string(raw))
		if findingWithID(findings, directoryCredentialAcquisitionRuleID) != nil {
			t.Fatalf("safe negative %q produced findings %v", command, FindingStrings(findings))
		}
	}
}
