// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The rules promoted to CRITICAL are the enforcement change this package exists to
// protect. Pin them so a later edit cannot silently return them to alert-only and
// take production-weighted enforcement recall back to zero.
func TestPromotedExactProofRulesEnforceInDefault(t *testing.T) {
	t.Parallel()
	for ruleID, want := range map[string]map[string]string{
		// Narrowed to the compromise half of the directory credential vocabulary:
		// a dump or an offline crack. The ticket-request half is a separate rule and
		// stays at HIGH in every profile.
		"credential.directory_credential_acquisition": {
			"permissive": "HIGH", "default": "CRITICAL", "strict": "CRITICAL",
		},
		"credential.directory_ticket_request": {
			"permissive": "HIGH", "default": "HIGH", "strict": "HIGH",
		},
		"tamper.pam_permit_authentication_bypass": {
			"permissive": "HIGH", "default": "CRITICAL", "strict": "CRITICAL",
		},
		"tamper.docker_insecure_http_registry": {
			"permissive": "HIGH", "default": "CRITICAL", "strict": "CRITICAL",
		},
		"tamper.windows_recursive_everyone_full_control": {
			"permissive": "HIGH", "default": "CRITICAL", "strict": "CRITICAL",
		},
		"persistence.global_ld_preload_install": {
			"permissive": "HIGH", "default": "CRITICAL", "strict": "CRITICAL",
		},
	} {
		for profile, wantSeverity := range want {
			if got := rulePackSeverity(t, profile, ruleID); got != wantSeverity {
				t.Errorf("%s/%s severity = %q, want %q", profile, ruleID, got, wantSeverity)
			}
		}
	}
}

// The default and permissive packs must carry an identical set of rule IDs and
// differ only in severity, and strict must remain a superset of default. Porting a
// rule into one pack and forgetting the others is the failure this catches.
func TestRulePackMembershipInvariants(t *testing.T) {
	t.Parallel()
	ids := func(profile string) map[string]struct{} {
		root := filepath.Join("..", "..", "policies", "guardrail", profile)
		pack, err := guardrail.LoadRulePack(root)
		if err != nil {
			t.Fatalf("load %s rule pack: %v", profile, err)
		}
		out := map[string]struct{}{}
		for _, file := range pack.RuleFiles {
			for _, rule := range file.Rules {
				out[rule.ID] = struct{}{}
			}
		}
		return out
	}
	defaultIDs, permissiveIDs, strictIDs := ids("default"), ids("permissive"), ids("strict")

	for id := range defaultIDs {
		if _, ok := permissiveIDs[id]; !ok {
			t.Errorf("rule %s is in default but missing from permissive", id)
		}
	}
	for id := range permissiveIDs {
		if _, ok := defaultIDs[id]; !ok {
			t.Errorf("rule %s is in permissive but missing from default", id)
		}
	}
	// CMD-WIN-RM-FORCE is a pre-existing, intentional default-only rule: strict
	// covers the same action through a broader recursive-delete rule.
	for id := range defaultIDs {
		if id == "CMD-WIN-RM-FORCE" {
			continue
		}
		if _, ok := strictIDs[id]; !ok {
			t.Errorf("rule %s is in default but missing from strict, so strict is weaker", id)
		}
	}

	if _, ok := defaultIDs["credential.directory_ticket_request"]; !ok {
		t.Error("rule credential.directory_ticket_request is missing from the default pack")
	}

	// These three stay strict-only on purpose. All were ported into default during
	// this work, measured, and reverted because each crosses a documented profile
	// boundary that the evidence did not justify moving:
	//
	//   exfil.literal_sensitive_json_upload / exfil.source_archive_external_transfer
	//     TestLiteralSensitiveUploadIsStrictDetectionOnly and
	//     TestSourceArchiveUploadIsStrictDetectionOnly encode the decision that the
	//     balanced profile stays quiet on a dual-use external upload, because an
	//     external credential backup or whole-repository export can be authorized.
	//
	//   chain.sensitive_sql_read_then_unbounded_delete_same_table
	//     impact.sql_destructive_mutation documents destructive SQL as "alert-only
	//     because these operations are dual-use without protected-scope policy", and
	//     TestStatefulBenchmarkCarriesAuthenticatedToolResourceIdentity pins default
	//     to alert and strict to block. Blocking destructive SQL is opt-in through
	//     strict or the database-destruction-protection pack.
	for _, id := range []string{
		"exfil.literal_sensitive_json_upload",
		"exfil.source_archive_external_transfer",
		"chain.sensitive_sql_read_then_unbounded_delete_same_table",
	} {
		if _, ok := defaultIDs[id]; ok {
			t.Errorf("rule %s is strict-only by design but appeared in the default pack", id)
		}
		if _, ok := strictIDs[id]; !ok {
			t.Errorf("rule %s should still be present in the strict pack", id)
		}
	}
}

func rulePackSeverity(t *testing.T, profile, ruleID string) string {
	t.Helper()
	root := filepath.Join("..", "..", "policies", "guardrail", profile)
	pack, err := guardrail.LoadRulePack(root)
	if err != nil {
		t.Fatalf("load %s rule pack: %v", profile, err)
	}
	for _, file := range pack.RuleFiles {
		for _, rule := range file.Rules {
			if rule.ID == ruleID {
				return rule.Severity
			}
		}
	}
	t.Fatalf("rule %s not found in %s profile", ruleID, profile)
	return ""
}
