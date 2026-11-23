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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestKnownCredentialReadTakesThePlainSpellingCellFiveTiers
// (rel-1-0-10:GAP-1244, GAP-0888, GAP-0898, GAP-0899; DET111 ruling
// 2026-11-22T04:12Z): a credential read the effects reader proves on a
// spelling the 1.0.10 readers do not place (${PWD%/proj}/..., a mounted
// home) gets, through decide.Decide, the verdict of the plain spelling
// cat <file> (the legacy rule naming the same file class), in the five tiers
// on the Claude Code and Codex hook routes. Each row runs the plain spelling
// through the hook, then hands the variant spelling's own decide.Input the
// known read finding the effects lane adds (raise only) and requires the
// plain verdict and severity. Before the read rows, that finding mapped by
// its own HIGH severity: an alert where cat ~/.ssh/id_rsa blocks (default,
// permissive, managed), an alert where another account's .git-credentials
// blocks (managed default) and an alert where one's own AWS credentials
// allow (permissive).
func TestKnownCredentialReadTakesThePlainSpellingCellFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	files := []string{".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".git-credentials", ".netrc",
		".npmrc", ".pypirc", ".kube/config", ".docker/config.json"}
	for _, f := range append(append([]string(nil), files...), "proj/notes.txt") {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")

	var last *decide.Input
	prev := decideRecordHook
	decideRecordHook = func(route, connector string, in decide.Input, out decide.Output) {
		if route == "single" {
			c := in
			last = &c
		}
	}
	t.Cleanup(func() { decideRecordHook = prev })

	type spelling struct {
		name, tail, plain, variant string
		target                     decide.TargetClass
	}
	var rows []spelling
	for _, f := range files {
		rows = append(rows,
			spelling{"own " + f, f, "cat " + home + "/" + f, "cat ${PWD%/proj}/" + f, decide.TargetCredential},
			spelling{"other " + f, f, "cat /home/bob/" + f, "cat ${PWD%/proj}/../bob/" + f, decide.TargetOtherHomeCredential},
		)
	}
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				set := decide.CredentialSet(row.tail)
				if set == "" {
					t.Fatalf("%s: no credential set for %q", row.name, row.tail)
				}
				last = nil
				plainAction, plainSeverity := route.decide(t, api, cwd, row.plain)
				if last == nil {
					t.Fatalf("%s %s %s: the plain spelling reached no decision", tier.name, route.connector, row.name)
				}
				plainIn := *last
				// The variant's own decision; a call with no finding reaches
				// none, and then its input is the plain call's (same
				// connector, tier, levels and deployment) with no finding.
				last = nil
				route.decide(t, api, cwd, row.variant)
				in := plainIn
				in.Findings = nil
				if last != nil {
					in = *last
				}
				variantAction := decideAction(decide.Decide(in).Action)
				proof := decide.Proof{Kind: decide.KindRead, Target: row.target, Certainty: decide.CertKnown, Set: set, Source: "effects"}
				in.Findings = append(append([]decide.Finding(nil), in.Findings...), decideFinding(RuleFinding{
					RuleID: decide.RuleFor(proof), Severity: "HIGH", Proof: proof,
				}))
				out := decide.Decide(in)
				if row.target == decide.TargetCredential {
					// One's own file: an effects read whose content stays
					// local is a shadow record (decide.RowEffectRead,
					// GAP-1825/1826): it does not move the variant's verdict.
					if got := decideAction(out.Action); got != variantAction {
						t.Errorf("%s %s %s: a local effects read of %q moves the verdict %s -> %s", tier.name, route.connector, row.name, row.variant, variantAction, got)
					}
					// With its content shown to the agent (GAP-1846) it takes
					// the plain spelling's cell, like another account's file.
					shown := proof
					shown.Flow = decide.FlowShown
					in.Findings[len(in.Findings)-1] = decideFinding(RuleFinding{RuleID: decide.RuleFor(shown), Severity: "HIGH", Proof: shown})
					if out := decide.Decide(in); decideAction(out.Action) != plainAction || out.Severity.String() != plainSeverity {
						t.Errorf("%s %s %s: a shown read of %q is %s/%s, want the plain spelling %q verdict %s/%s",
							tier.name, route.connector, row.name, row.variant, decideAction(out.Action), out.Severity, row.plain, plainAction, plainSeverity)
					}
					continue
				}
				if got := decideAction(out.Action); got != plainAction || out.Severity.String() != plainSeverity {
					t.Errorf("%s %s %s: known read of %q is %s/%s, want the plain spelling %q verdict %s/%s",
						tier.name, route.connector, row.name, row.variant, got, out.Severity, row.plain, plainAction, plainSeverity)
				}
				if want := map[string]string{decide.SetSSHPrivateKey: "PATH-SSH-KEY", decide.SetGitCredentials: "PATH-GIT-CREDS"}[set]; want != "" && out.Action != decide.Allow {
					if len(out.RuleIDs) == 0 || out.RuleIDs[len(out.RuleIDs)-1] != want {
						t.Errorf("%s %s %s: rule ids %v, want %s named", tier.name, route.connector, row.name, out.RuleIDs, want)
					}
				}
			}
		}
	}
}

type readRowRoute struct {
	connector string
	decide    func(t *testing.T, api *APIServer, cwd, command string) (action, severity string)
}

func r3PosixRoutesForReadRows() []readRowRoute {
	return []readRowRoute{
		{"claudecode", func(t *testing.T, api *APIServer, cwd, command string) (string, string) {
			resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-read-rows", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Severity
		}},
		{"codex", func(t *testing.T, api *APIServer, cwd, command string) (string, string) {
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Severity
		}},
	}
}
