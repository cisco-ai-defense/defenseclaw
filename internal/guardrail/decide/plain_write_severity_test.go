// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlainWriteSeverityIsThePackSeverity pins plainWriteSeverity to the
// shipped packs: a Known protected write carries the severity each pack
// gives the 1.0.10 rule the plain spelling fires (GAP-1478, GAP-1500).
func TestPlainWriteSeverityIsThePackSeverity(t *testing.T) {
	for _, pack := range []string{"default", "strict", "permissive"} {
		files, err := filepath.Glob(filepath.Join("..", "..", "..", "policies", "guardrail", pack, "rules", "*.yaml"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s pack rules: %v (%d files)", pack, err, len(files))
		}
		got := map[string]string{}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			id := ""
			for _, line := range strings.Split(string(data), "\n") {
				field := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
				switch {
				case strings.HasPrefix(field, "id:"):
					id = strings.ToUpper(strings.Trim(strings.TrimSpace(strings.TrimPrefix(field, "id:")), `"'`))
				case strings.HasPrefix(field, "severity:") && id != "":
					if _, seen := got[id]; !seen {
						got[id] = strings.ToUpper(strings.Trim(strings.TrimSpace(strings.TrimPrefix(field, "severity:")), `"'`))
					}
					id = ""
				}
			}
		}
		for rule, want := range plainWriteSeverity {
			if got[strings.ToUpper(rule)] != want.String() {
				t.Errorf("%s pack: %s severity %q, plainWriteSeverity %s", pack, rule, got[strings.ToUpper(rule)], want)
			}
		}
	}
}

// TestRuleForNamesEveryPlainWriteRule: every rule a Known write proof names
// has its pack severity in plainWriteSeverity, and an own SSH private key
// write names none (GAP-1878).
func TestRuleForNamesEveryPlainWriteRule(t *testing.T) {
	proofs := []Proof{
		{Kind: KindWrite, Target: TargetAuthorizedKeys, Certainty: CertKnown},
		{Kind: KindAppend, Target: TargetState, Certainty: CertKnown},
		{Kind: KindWrite, Target: TargetHookConfig, Certainty: CertKnown},
	}
	for set := range setRules {
		proofs = append(proofs, Proof{Kind: KindAppend, Target: TargetCredential, Certainty: CertKnown, Set: set})
	}
	for _, p := range proofs {
		rule := RuleFor(p)
		if p.Set == SetSSHPrivateKey {
			if rule != "" {
				t.Errorf("own SSH private key write names %q, want none (GAP-1878)", rule)
			}
			continue
		}
		if _, ok := plainWriteSeverity[rule]; rule == "" || !ok {
			t.Errorf("%+v: rule %q has no plain write severity", p, rule)
		}
	}
	// T23b still names the own key class for link and permission proofs;
	// GAP-1878 excludes its write, append and delete spellings only.
	for _, kind := range []ProofKind{KindLink, KindPerm} {
		p := Proof{Kind: kind, Target: TargetCredential, Certainty: CertKnown, Set: SetSSHPrivateKey}
		if got := RuleFor(p); got != "PATH-SSH-KEY" {
			t.Errorf("own SSH private key %v names %q, want PATH-SSH-KEY", kind, got)
		}
	}
	// rm FILE fires the hook config guard and the credential file rules, so a
	// Known delete names them as the plain spelling does (GAP-1478).
	if got := RuleFor(Proof{Kind: KindDelete, Target: TargetHookConfig, Certainty: CertKnown}); got != RuleHookConfigWrite {
		t.Errorf("a hook config delete names %q, want %q", got, RuleHookConfigWrite)
	}
	if got := RuleFor(Proof{Kind: KindDelete, Target: TargetCredential, Certainty: CertKnown, Set: SetAWSCredentials}); got != "PATH-AWS-CREDS" {
		t.Errorf("an AWS credentials delete names %q, want PATH-AWS-CREDS", got)
	}
	if RuleFor(Proof{Kind: KindWrite, Target: TargetHookConfig, Certainty: CertMaybe}) != "" {
		t.Error("a Maybe hook config write names a rule")
	}
}

// TestKnownProtectedWriteRowNamesEveryPlainWriteRule: the row lists every
// rule that has a plain write severity, and no other.
func TestKnownProtectedWriteRowNamesEveryPlainWriteRule(t *testing.T) {
	if len(knownProtectedWriteRules) != len(plainWriteSeverity) {
		t.Fatalf("row rules %v, severity table %v", knownProtectedWriteRules, plainWriteSeverity)
	}
	for _, rule := range knownProtectedWriteRules {
		if _, ok := plainWriteSeverity[rule]; !ok {
			t.Errorf("row rule %s has no plain write severity", rule)
		}
	}
}
