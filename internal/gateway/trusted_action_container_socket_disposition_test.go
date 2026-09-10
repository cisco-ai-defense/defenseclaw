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
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const containerSocketDispositionRuleID = "privilege.container_runtime_socket_access"

func TestTrustedActionContainerSocketPassiveAccessIsAuditOnly(t *testing.T) {
	for _, profile := range []string{"default", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			generation := containerSocketDispositionGeneration(t, profile)
			for _, command := range []string{
				"cat /var/run/docker.sock",
				"ls -la /var/run/docker.sock",
				"stat /var/run/docker.sock",
			} {
				command := command
				t.Run(command, func(t *testing.T) {
					facts := actionfacts.Analyze(actionfacts.Input{
						Tool:       "shell",
						Command:    command,
						CWD:        "/repo",
						ActiveHome: "/home/alice",
					})
					got := applyTrustedActionContextDisposition(
						generation,
						facts,
						[]RuleFinding{containerSocketDispositionFinding(t, generation)},
					)
					assertContainerSocketAuditOnly(t, got)
				})
			}
		})
	}
}

func TestTrustedActionContainerSocketAuthoritativeUseRemainsAlertCapable(t *testing.T) {
	generation := containerSocketDispositionGeneration(t, "default")
	for _, command := range []string{
		"docker -H unix:///var/run/docker.sock ps",
		"curl --unix-socket /run/containerd/containerd.sock http://localhost/version",
		"docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
	} {
		command := command
		t.Run(command, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:       "shell",
				Command:    command,
				CWD:        "/repo",
				ActiveHome: "/home/alice",
			})
			got := applyTrustedActionContextDisposition(
				generation,
				facts,
				[]RuleFinding{containerSocketDispositionFinding(t, generation)},
			)
			if len(got) != 1 || !got[0].contributesToEnforcement() ||
				got[0].disposition == findingDispositionAudit ||
				!got[0].proof.authorizes(got[0].RuleID) {
				t.Fatalf("authoritative socket use = %#v, want alert-capable complete proof", got)
			}
		})
	}
}

func TestTrustedActionContainerSocketStructuredWriteRemainsAlertCapable(t *testing.T) {
	generation := containerSocketDispositionGeneration(t, "default")
	facts := actionfacts.Facts{
		Tool:  "write_file",
		Parse: actionfacts.ParseResult{Status: actionfacts.StatusComplete},
		Commands: []actionfacts.CommandFact{{
			ID:           1,
			Kind:         actionfacts.CommandKindProcess,
			Effect:       actionfacts.EffectExecute,
			Executable:   "write_file",
			Program:      "write_file",
			ArgvComplete: true,
			Operations:   []actionfacts.OperationKind{actionfacts.OperationWrite},
		}},
		Paths: []actionfacts.PathFact{{
			CommandID:  1,
			Access:     actionfacts.PathAccessWrite,
			Flavor:     actionfacts.PathFlavorPOSIX,
			Value:      "/var/run/docker.sock",
			Normalized: "/var/run/docker.sock",
			Absolute:   true,
			Resolved:   "/var/run/docker.sock",
		}},
	}
	got := applyTrustedActionContextDisposition(
		generation,
		facts,
		[]RuleFinding{containerSocketDispositionFinding(t, generation)},
	)
	if len(got) != 1 || !got[0].contributesToEnforcement() ||
		!got[0].proof.authorizes(got[0].RuleID) {
		t.Fatalf("authoritative socket write = %#v, want alert-capable complete proof", got)
	}
}

func TestTrustedActionContainerSocketUnresolvedStrictVisibilityCannotBlock(t *testing.T) {
	generation := containerSocketDispositionGeneration(t, "strict")
	facts := actionfacts.Facts{
		Parse: actionfacts.ParseResult{Status: actionfacts.StatusPartial},
	}
	got := applyTrustedActionContextDisposition(
		generation,
		facts,
		[]RuleFinding{containerSocketDispositionFinding(t, generation)},
	)
	assertContainerSocketAuditOnly(t, got)
}

func containerSocketDispositionGeneration(
	t *testing.T,
	profile string,
) *compiledRulePackCategories {
	t.Helper()
	pack := mustLoadRulePack(
		t,
		filepath.Join(guardrailPoliciesRoot(t), profile),
	)
	generation, err := compileRulePackCategories(pack)
	if err != nil {
		t.Fatalf("compile %s rule pack: %v", profile, err)
	}
	return generation
}

func containerSocketDispositionFinding(
	t *testing.T,
	generation *compiledRulePackCategories,
) RuleFinding {
	t.Helper()
	_, rule, ok := trustedActionCatalogRule(
		generation,
		containerSocketDispositionRuleID,
	)
	if !ok {
		t.Fatalf("rule %q not found", containerSocketDispositionRuleID)
	}
	return RuleFinding{
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Severity,
		Confidence:  rule.Confidence,
		Tags:        append([]string(nil), rule.Tags...),
		enforcement: findingEnforcementAllowed,
	}
}

func assertContainerSocketAuditOnly(t *testing.T, got []RuleFinding) {
	t.Helper()
	if len(got) != 1 || got[0].contributesToEnforcement() ||
		got[0].disposition != findingDispositionAudit ||
		got[0].Severity != "LOW" {
		t.Fatalf("socket reference = %#v, want one LOW audit-only finding", got)
	}
}
