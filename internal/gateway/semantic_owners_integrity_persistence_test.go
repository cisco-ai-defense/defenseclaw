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
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

func TestSemanticIntegrityPersistenceOwnerContract(t *testing.T) {
	wantIDs := []string{
		"C2-METADATA-AWS",
		"CMD-CRONTAB",
		"CMD-SYSTEMCTL",
		"COG-AGENTS-MD",
		"COG-MEMORY",
		"COG-OPENCLAW-JSON",
		"PATH-ETC-SUDOERS",
		"PATH-HISTORY",
		"PATH-SSH-DIR",
		"integrity.git_hooks_bypass",
		"integrity.history_tamper",
		"persistence.git_hook_write",
		"persistence.shell_profile_write",
		"persistence.ssh_authorized_keys_command",
		"privilege.container_runtime_socket_access",
		"source.git_config_exec",
		"source.git_remote_tamper",
		"tamper.detector_state_write",
	}
	gotIDs := make([]string, 0, len(semanticIntegrityPersistenceOwners))
	for id := range semanticIntegrityPersistenceOwners {
		gotIDs = append(gotIDs, id)
	}
	slices.Sort(gotIDs)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("owner IDs = %v, want %v", gotIDs, wantIDs)
	}

	metadata := semanticIntegrityPersistenceOwners["C2-METADATA-AWS"]
	wantMetadataAliases := []string{
		"C2-METADATA-GCP",
		"C2-METADATA-AZURE",
		"C2-METADATA-HEX",
		"C2-METADATA-DECIMAL",
		"C2-METADATA-OCTAL",
	}
	if !slices.Equal(metadata.equivalentAliases, wantMetadataAliases) {
		t.Fatalf(
			"metadata aliases = %v, want %v",
			metadata.equivalentAliases,
			wantMetadataAliases,
		)
	}
	if got := semanticIntegrityPersistenceFallbackAliasesOnMatch["persistence.ssh_authorized_keys_command"]; !slices.Equal(got, []string{"PATH-SSH-DIR"}) {
		t.Fatalf("N23 fallback aliases = %v", got)
	}
	if got := semanticOwnerForRule(
		"persistence.ssh_authorized_keys_command",
	).fallbackAliasesOnMatch; !slices.Equal(got, []string{"PATH-SSH-DIR"}) {
		t.Fatalf("integrated N23 fallback aliases = %v", got)
	}
	history := semanticOwnerForRule("integrity.history_tamper")
	if slices.Contains(history.claimedIDs(true), "PATH-HISTORY") {
		t.Fatal("command history owner claimed the filesystem history rule")
	}
}

func TestActiveAgentInstructionMutationRequiresExactTrustedPath(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name             string
		ruleID           string
		command          string
		dialect          actionfacts.Dialect
		activeFiles      []string
		contextUncertain bool
		want             bool
		wantSafe         bool
	}{
		{
			name:        "active AGENTS mutation",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /repo/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
			want:        true,
		},
		{
			name:        "unresolved POSIX parent variant is not declared safe",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /repo/AGENTS.md",
			activeFiles: []string{"/Repo/AGENTS.md"},
		},
		{
			name:        "untrusted lowercase active basename stays inactive",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /repo/agents.md",
			activeFiles: []string{"/repo/agents.md"},
			wantSafe:    true,
		},
		{
			name:        "Windows path identity folds case",
			ruleID:      "COG-AGENTS-MD",
			command:     `Set-Content -LiteralPath 'C:\Repo\AGENTS.md' -Value updated`,
			dialect:     actionfacts.DialectPowerShell,
			activeFiles: []string{`c:\repo\agents.MD`},
			want:        true,
		},
		{
			name:        "Windows distinct path is not declared safe",
			ruleID:      "COG-AGENTS-MD",
			command:     `Set-Content -LiteralPath 'C:\Repo\AGENTS.md' -Value updated`,
			dialect:     actionfacts.DialectPowerShell,
			activeFiles: []string{`C:\Other\AGENTS.md`},
		},
		{
			name:        "active MEMORY mutation",
			ruleID:      "COG-MEMORY",
			command:     "printf updated >> /repo/MEMORY.md",
			activeFiles: []string{"/repo/MEMORY.md"},
			want:        true,
		},
		{
			name:        "ordinary active-file read",
			ruleID:      "COG-AGENTS-MD",
			command:     "cat /repo/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
			wantSafe:    true,
		},
		{
			name:        "distinct same basename is not declared safe",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /repo/other/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
		},
		{
			name:        "external alias shape is not declared safe",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /tmp/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
		},
		{
			name:        "fixture alias shape is not declared safe",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /repo/testdata/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
		},
		{
			name:        "other instruction kind proves known empty",
			ruleID:      "COG-AGENTS-MD",
			command:     "printf updated > /tmp/AGENTS.md",
			activeFiles: []string{"/repo/MEMORY.md"},
			wantSafe:    true,
		},
		{
			name:     "missing active context",
			ruleID:   "COG-MEMORY",
			command:  "printf updated > /repo/MEMORY.md",
			wantSafe: true,
		},
		{
			name:             "uncertain context fails closed for exact mutation",
			ruleID:           "COG-MEMORY",
			command:          "printf updated > /repo/MEMORY.md",
			contextUncertain: true,
			want:             true,
		},
		{
			name:             "uncertain context does not declare folded basename safe",
			ruleID:           "COG-AGENTS-MD",
			command:          "printf updated > /repo/agents.md",
			contextUncertain: true,
		},
		{
			name:             "uncertain context preserves Windows case folding",
			ruleID:           "COG-AGENTS-MD",
			command:          `Set-Content -LiteralPath 'C:\Repo\agents.md' -Value updated`,
			dialect:          actionfacts.DialectPowerShell,
			contextUncertain: true,
			want:             true,
		},
		{
			name:             "uncertain context does not turn reads into mutations",
			ruleID:           "COG-AGENTS-MD",
			command:          "cat /repo/AGENTS.md",
			contextUncertain: true,
			wantSafe:         true,
		},
		{
			name:        "filename mention",
			ruleID:      "COG-AGENTS-MD",
			command:     "rg -n AGENTS.md internal/gateway",
			activeFiles: []string{"/repo/AGENTS.md"},
			wantSafe:    true,
		},
		{
			name:        "external path mention",
			ruleID:      "COG-AGENTS-MD",
			command:     "echo /tmp/AGENTS.md",
			activeFiles: []string{"/repo/AGENTS.md"},
			wantSafe:    true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:                      "shell",
				Command:                   test.command,
				DialectHint:               test.dialect,
				CWD:                       "/repo",
				ActiveHome:                "/home/alice",
				ActiveAgentFiles:          test.activeFiles,
				ActiveAgentFilesUncertain: test.contextUncertain,
			})
			requireAuthoritativeIntegrityFacts(t, facts)
			owner, ok := semanticIntegrityPersistenceOwners[test.ruleID]
			if !ok {
				t.Fatalf("owner %q is missing", test.ruleID)
			}
			if got := owner.prerequisite(facts); got != test.want {
				t.Fatalf("prerequisite=%t, want %t; facts=%+v", got, test.want, facts)
			}
			if !test.want {
				if got := owner.suppressFallback(facts); got != test.wantSafe {
					t.Fatalf("safe negative=%t, want %t; facts=%+v", got, test.wantSafe, facts)
				}
			}
		})
	}
}

func TestActiveAgentInstructionMutationUsesCachedPOSIXCaseSemantics(t *testing.T) {
	const activePath = "/repo/AGENTS.md"
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:                            "shell",
		Command:                         "printf updated > /repo/agents.md",
		CWD:                             "/repo",
		ActiveAgentFiles:                []string{activePath},
		ActiveAgentFilesCaseInsensitive: []string{activePath},
	})
	requireAuthoritativeIntegrityFacts(t, facts)
	owner := semanticIntegrityPersistenceOwners["COG-AGENTS-MD"]
	if !owner.prerequisite(facts) {
		t.Fatalf("cached basename casing alias did not match: %+v", facts)
	}
	if projected := facts.EnforcementProjection(); !owner.prerequisite(projected) {
		t.Fatalf(
			"eligible active mutation did not survive enforcement projection: %+v",
			projected,
		)
	}

	facts.ActiveAgentFilesCaseInsensitive = nil
	if owner.prerequisite(facts) || owner.suppressFallback(facts) {
		t.Fatalf("unmarked POSIX case variant was declared safe: %+v", facts)
	}

	parentVariant := actionfacts.Analyze(actionfacts.Input{
		Tool:                            "shell",
		Command:                         "printf updated > /repo/agents.md",
		CWD:                             "/repo",
		ActiveAgentFiles:                []string{"/Repo/AGENTS.md"},
		ActiveAgentFilesCaseInsensitive: []string{"/Repo/AGENTS.md"},
	})
	if owner.prerequisite(parentVariant) || owner.suppressFallback(parentVariant) {
		t.Fatalf("unproven parent alias was enforced or declared safe: %+v", parentVariant)
	}
	if activeAgentInstructionPathsMatch(
		activePath,
		"/repo/AGENTſ.md",
		actionfacts.PathFlavorPOSIX,
		true,
	) {
		t.Fatal("ASCII load proof accepted a Unicode simple-fold alias")
	}
}

func TestTrustedActionActiveInstructionFilesystemIdentityDispatch(t *testing.T) {
	const connector = "active-instruction-filesystem-identity-dispatch"
	installDefaultProfileConnector(t, connector)

	dispatch := func(input actionfacts.Input) []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:              input,
			LegacyText:         input.Command,
			Connector:          connector,
			EnforcementCapable: true,
		})
	}

	t.Run("cached POSIX filename casing alias enforces", func(t *testing.T) {
		const activePath = "/repo/AGENTS.md"
		const command = "printf updated > /repo/agents.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                            "shell",
			Command:                         command,
			CWD:                             "/repo",
			ActiveAgentFiles:                []string{activePath},
			ActiveAgentFilesCaseInsensitive: []string{activePath},
		}), "COG-AGENTS-MD")
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("cached case alias finding = %+v, want enforcement", finding)
		}
	})

	t.Run("unmarked POSIX casing alias remains detection only", func(t *testing.T) {
		const command = "printf updated > /repo/agents.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "shell",
			Command:          command,
			CWD:              "/repo",
			ActiveAgentFiles: []string{"/repo/AGENTS.md"},
		}), "COG-AGENTS-MD")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf("unmarked POSIX case alias finding = %+v, want detection-only", finding)
		}
	})

	t.Run("uncertain context does not fold candidate casing", func(t *testing.T) {
		if finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                      "shell",
			Command:                   "printf updated > /repo/agents.md",
			CWD:                       "/repo",
			ActiveAgentFilesUncertain: true,
		}), "COG-AGENTS-MD"); finding != nil && finding.contributesToEnforcement() {
			t.Fatalf("uncertain context enforced a folded-case candidate: %+v", *finding)
		}
	})

	t.Run("uncertain context folds only with lost case proof", func(t *testing.T) {
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                                     "shell",
			Command:                                  "printf updated > /repo/agents.md",
			CWD:                                      "/repo",
			ActiveAgentFilesCaseInsensitiveUncertain: true,
			ActiveAgentFilesUncertain:                true,
		}), "COG-AGENTS-MD")
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("lost case proof did not enforce folded candidate: %+v", finding)
		}
	})

	t.Run("uncertain context checks retained exact entries first", func(t *testing.T) {
		const activePath = "/repo/AGENTS.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                            "shell",
			Command:                         "printf updated > /repo/agents.md",
			CWD:                             "/repo",
			ActiveAgentFiles:                []string{activePath},
			ActiveAgentFilesCaseInsensitive: []string{activePath},
			ActiveAgentFilesUncertain:       true,
		}), "COG-AGENTS-MD")
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("retained exact case proof was ignored: %+v", finding)
		}
	})

	t.Run("cached basename proof does not enforce parent alias", func(t *testing.T) {
		const activePath = "/Repo/AGENTS.md"
		const command = "printf updated > /repo/agents.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                            "shell",
			Command:                         command,
			CWD:                             "/repo",
			ActiveAgentFiles:                []string{activePath},
			ActiveAgentFilesCaseInsensitive: []string{activePath},
		}), "COG-AGENTS-MD")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf("unproven parent alias finding = %+v, want detection-only", finding)
		}
	})

	t.Run("distinct same-kind POSIX path remains detection only", func(t *testing.T) {
		const activePath = "/repo/MEMORY.md"
		const command = "printf updated > /repo/unrelated/memory.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:                            "shell",
			Command:                         command,
			CWD:                             "/repo",
			ActiveAgentFiles:                []string{activePath},
			ActiveAgentFilesCaseInsensitive: []string{activePath},
		}), "COG-MEMORY")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf("distinct same-kind finding = %+v, want detection-only", finding)
		}
	})

	t.Run("external lexical alias remains detection only", func(t *testing.T) {
		const command = "printf updated > /tmp/AGENTS.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "shell",
			Command:          command,
			CWD:              "/repo",
			ActiveAgentFiles: []string{"/repo/AGENTS.md"},
		}), "COG-AGENTS-MD")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf("external alias finding = %+v, want detection-only", finding)
		}
	})

	t.Run("fixture-shaped lexical alias remains detection only", func(t *testing.T) {
		const command = "printf updated > /repo/testdata/AGENTS.md"
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "shell",
			Command:          command,
			CWD:              "/repo",
			ActiveAgentFiles: []string{"/repo/AGENTS.md"},
		}), "COG-AGENTS-MD")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf("fixture alias finding = %+v, want detection-only", finding)
		}
	})

	t.Run("known-empty instruction context stays quiet", func(t *testing.T) {
		for _, activeFiles := range [][]string{
			nil,
			{"/repo/MEMORY.md"},
		} {
			if finding := findingWithID(dispatch(actionfacts.Input{
				Tool:             "shell",
				Command:          "printf updated > /tmp/AGENTS.md",
				CWD:              "/repo",
				ActiveAgentFiles: activeFiles,
			}), "COG-AGENTS-MD"); finding != nil {
				t.Fatalf("known-empty context produced finding: %+v", *finding)
			}
		}
	})

	t.Run("distinct active-file read stays quiet", func(t *testing.T) {
		if finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "shell",
			Command:          "cat /tmp/AGENTS.md",
			CWD:              "/repo",
			ActiveAgentFiles: []string{"/repo/AGENTS.md"},
		}), "COG-AGENTS-MD"); finding != nil {
			t.Fatalf("read-only alias produced finding: %+v", *finding)
		}
	})

	t.Run("external active-file mention stays quiet", func(t *testing.T) {
		if finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "shell",
			Command:          "echo /tmp/AGENTS.md",
			CWD:              "/repo",
			ActiveAgentFiles: []string{"/repo/AGENTS.md"},
		}), "COG-AGENTS-MD"); finding != nil {
			t.Fatalf("external path mention produced finding: %+v", *finding)
		}
	})

	t.Run("Windows case folding enforces", func(t *testing.T) {
		const command = `Set-Content -LiteralPath 'C:\Repo\agents.md' -Value updated`
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "PowerShell",
			Command:          command,
			CWD:              `C:\Repo`,
			ActiveAgentFiles: []string{`c:\repo\AGENTS.MD`},
		}), "COG-AGENTS-MD")
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("Windows case-folded finding = %+v, want enforcement", finding)
		}
	})

	t.Run("preview active mutation cannot borrow unrelated execution", func(t *testing.T) {
		const command = `Set-Content -LiteralPath 'C:\Repo\AGENTS.md' -Value preview -WhatIf; Set-Content -LiteralPath 'C:\Repo\notes.txt' -Value updated`
		finding := findingWithID(dispatch(actionfacts.Input{
			Tool:             "PowerShell",
			Command:          command,
			CWD:              `C:\Repo`,
			ActiveAgentFiles: []string{`C:\Repo\AGENTS.md`},
		}), "COG-AGENTS-MD")
		if finding == nil || finding.contributesToEnforcement() {
			t.Fatalf(
				"preview mutation finding = %+v, want detection-only",
				finding,
			)
		}
	})
}

func TestActiveAgentInstructionMutationUnresolvedCandidateIsNotSafe(t *testing.T) {
	t.Parallel()

	facts := actionfacts.Facts{
		Parse: actionfacts.ParseResult{Status: actionfacts.StatusComplete},
		Commands: []actionfacts.CommandFact{{
			ID:           1,
			Kind:         actionfacts.CommandKindProcess,
			Effect:       actionfacts.EffectExecute,
			Program:      "printf",
			Executable:   "printf",
			Argv:         []string{"printf", "updated", "AGENTS.md"},
			ArgvComplete: true,
			Operations:   []actionfacts.OperationKind{actionfacts.OperationWrite},
		}},
	}
	owner := semanticIntegrityPersistenceOwners["COG-AGENTS-MD"]
	if owner.prerequisite(facts) {
		t.Fatal("unresolved instruction-file candidate satisfied the semantic owner")
	}
	if owner.suppressFallback(facts) {
		t.Fatal("unresolved instruction-file candidate suppressed detection fallback")
	}
}

func TestSemanticIntegrityPersistenceExpressionsCompile(t *testing.T) {
	t.Parallel()

	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	for name, expression := range map[string]string{
		"history tamper":                    semanticHistoryTamperExpression,
		"active agent instruction mutation": semanticActiveAgentInstructionMutationExpression,
	} {
		if _, code := compiler.Compile(expression); code != semantic.CompileOK {
			t.Fatalf("%s compile code = %q", name, code)
		}
	}
}

func TestGeneratedActiveInstructionRulesUseFilesystemNeutralExpression(t *testing.T) {
	t.Parallel()

	generation := snapshotRulePackGeneration("")
	if generation == nil {
		t.Fatal("default rule generation is unavailable")
	}
	want := map[string]bool{
		"COG-AGENTS-MD": false,
		"COG-MEMORY":    false,
	}
	for _, candidate := range generation.semanticRules {
		if _, ok := want[candidate.rule.ID]; !ok {
			continue
		}
		if candidate.rule.Expression != semanticActiveAgentInstructionMutationExpression {
			t.Fatalf(
				"%s expression = %q, want filesystem-neutral owner gate",
				candidate.rule.ID,
				candidate.rule.Expression,
			)
		}
		want[candidate.rule.ID] = true
	}
	for ruleID, found := range want {
		if !found {
			t.Fatalf("default semantic rule %q is missing", ruleID)
		}
	}
}

func TestTypedGuardrailsOffProofIsExact(t *testing.T) {
	if typedGuardrailsOffRuleID != "tamper.guardrails_off" {
		t.Fatalf("typed rule ID = %q", typedGuardrailsOffRuleID)
	}
	if !provesTypedGuardrailsOff(
		"guardrail_config_change",
		true,
		true,
		false,
		actionfacts.EffectExecute,
	) {
		t.Fatal("trusted enforcement-on to enforcement-off transition was rejected")
	}
	for _, test := range []struct {
		name     string
		kind     string
		trusted  bool
		previous bool
		next     bool
		effect   actionfacts.CommandEffect
	}{
		{"untrusted", "guardrail_config_change", false, true, false, actionfacts.EffectExecute},
		{"wrong kind", "tool_call", true, true, false, actionfacts.EffectExecute},
		{"already off", "guardrail_config_change", true, false, false, actionfacts.EffectExecute},
		{"still on", "guardrail_config_change", true, true, true, actionfacts.EffectExecute},
		{"preview", "guardrail_config_change", true, true, false, actionfacts.EffectPreview},
	} {
		t.Run(test.name, func(t *testing.T) {
			if provesTypedGuardrailsOff(
				test.kind,
				test.trusted,
				test.previous,
				test.next,
				test.effect,
			) {
				t.Fatal("invalid typed transition was accepted")
			}
		})
	}
}

func TestIntegrityPersistenceCommandPrerequisites(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect actionfacts.Dialect
		ownerID string
		want    bool
	}{
		{"crontab file install", "crontab /tmp/jobs", "", "CMD-CRONTAB", true},
		{"crontab list", "crontab -l", "", "CMD-CRONTAB", false},
		{"crontab removal", "crontab -r", "", "CMD-CRONTAB", false},
		{"systemctl enable", "systemctl enable --now demo.service", "", "CMD-SYSTEMCTL", true},
		{"systemctl detached job mode", "systemctl --job-mode fail enable demo.service", "", "CMD-SYSTEMCTL", true},
		{"systemctl status", "systemctl status demo.service", "", "CMD-SYSTEMCTL", false},
		{"systemctl dry run", "systemctl --dry-run enable demo.service", "", "CMD-SYSTEMCTL", false},
		{"launchctl bootstrap", "launchctl bootstrap gui/501 /Library/LaunchAgents/demo.plist", "", "CMD-SYSTEMCTL", true},
		{"git commit no verify", "git commit --no-verify -m fixture", "", "integrity.git_hooks_bypass", true},
		{"git commit normal", "git commit -m fixture", "", "integrity.git_hooks_bypass", false},
		{"git scoped hooks off", "git -c core.hooksPath=/dev/null commit -m fixture", "", "integrity.git_hooks_bypass", true},
		{"git push no verify", "git push --no-verify origin main", "", "integrity.git_hooks_bypass", true},
		{"git push dry run", "git push -n origin main", "", "integrity.git_hooks_bypass", false},
		{"git empty hooks path", "git config core.hooksPath ''", "", "integrity.git_hooks_bypass", true},
		{"git nonempty hooks path", "git config core.hooksPath .githooks", "", "integrity.git_hooks_bypass", false},
		{"git remote tamper", "git remote set-url origin https://sink.invalid/repo.git", "", "source.git_remote_tamper", true},
		{"git remote list", "git remote -v", "", "source.git_remote_tamper", false},
		{"git executable config", "git config core.sshCommand /tmp/wrap-ssh", "", "source.git_config_exec", true},
		{"git shell alias", "git config alias.deploy '!sh deploy.sh'", "", "source.git_config_exec", true},
		{"git read overwrites active config", "git show --output=.git/config HEAD", "", "source.git_config_exec", true},
		{"git read overwrites config after chdir", "git -C project show --output=.git/config HEAD", "", "source.git_config_exec", true},
		{"git read overwrites config after joined chdir", "git -Cproject show --output=.git/config HEAD", "", "source.git_config_exec", true},
		{"git read overwrites explicit git dir config", "git --git-dir=.git show --output=.git/config HEAD", "", "source.git_config_exec", true},
		{"git read overwrites separate git dir config", "git --git-dir .git show --output=.git/config HEAD", "", "source.git_config_exec", true},
		{"PowerShell git read overwrites config after chdir", `git -C project show --output=.git\config HEAD`, actionfacts.DialectPowerShell, "source.git_config_exec", true},
		{"git read targets different git dir", "git --git-dir=other.git show --output=.git/config HEAD", "", "source.git_config_exec", false},
		{"git bare read does not overwrite active config", "git --bare show --output=.git/config HEAD", "", "source.git_config_exec", false},
		{"git read overwrites hook after chdir", "git -C project diff --output=.git/hooks/pre-commit HEAD^ HEAD", "", "persistence.git_hook_write", true},
		{"PowerShell git read overwrites hook after chdir", `git -C project diff --output=.git\hooks\pre-commit HEAD^ HEAD`, actionfacts.DialectPowerShell, "persistence.git_hook_write", true},
		{"git bare read does not overwrite active hook", "git --bare diff --output=.git/hooks/pre-commit HEAD^ HEAD", "", "persistence.git_hook_write", false},
		{"git read writes ordinary output", "git show --output=release.txt HEAD", "", "source.git_config_exec", false},
		{"git benign config", "git config user.email dev@example.invalid", "", "source.git_config_exec", false},
		{"git safe credential helper", "git config credential.helper '!gh auth git-credential'", "", "source.git_config_exec", false},
		{"history read", "history", "", "integrity.history_tamper", false},
		{"history clear mention", "printf '%s\\n' 'history -c'", "", "integrity.history_tamper", false},
		{"unset history file", "unset HISTFILE", "", "integrity.history_tamper", true},
		{"unset history file with sibling", "unset HISTSIZE HISTFILE", "", "integrity.history_tamper", true},
		{"unset history variable mode", "unset -v HISTFILE", "", "integrity.history_tamper", true},
		{"unset history after delimiter", "unset -- HISTFILE", "", "integrity.history_tamper", true},
		{"unset function", "unset -f HISTFILE", "", "integrity.history_tamper", false},
		{"unset function and variable is invalid", "unset -fv HISTFILE", "", "integrity.history_tamper", false},
		{"unset other variable", "unset HISTSIZE", "", "integrity.history_tamper", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cwd := "/repo"
			activeHome := "/home/alice"
			if test.dialect == actionfacts.DialectPowerShell {
				cwd = `C:\repo`
				activeHome = `C:\Users\alice`
			}
			facts := analyzeIntegrityCommand(
				t,
				test.command,
				test.dialect,
				cwd,
				activeHome,
			)
			owner := semanticIntegrityPersistenceOwners[test.ownerID]
			if got := owner.prerequisite(facts); got != test.want {
				t.Fatalf(
					"prerequisite = %t, want %t; facts=%+v",
					got,
					test.want,
					facts,
				)
			}
		})
	}

	if verb, ok := integrityFirstPositional([]string{
		"systemctl", "--future-mode", "enable", "demo.service",
	}); ok || verb != "" {
		t.Fatalf("unknown detached option produced verb %q", verb)
	}

	if gitNoVerify([]string{"commit", "-m", "-n"}) {
		t.Fatal("-n used as the message value became a no-verify flag")
	}

	configOwner := semanticIntegrityPersistenceOwners["source.git_config_exec"]
	fixtureConfig := analyzeIntegrityCommand(
		t,
		"git config --file /repo/testdata/config core.sshCommand /tmp/wrap",
		"",
		"/repo",
		"/home/alice",
	)
	activeConfig := analyzeIntegrityCommand(
		t,
		"git config --file /home/alice/.gitconfig core.sshCommand /tmp/wrap",
		"",
		"/repo",
		"/home/alice",
	)
	escapedConfig := analyzeIntegrityCommand(
		t,
		"git config --file ../live/.gitconfig core.sshCommand /tmp/wrap",
		"",
		"/repo/fixtures",
		"/home/alice",
	)
	if configOwner.prerequisite(fixtureConfig) ||
		!configOwner.suppressFallback(fixtureConfig) ||
		configOwner.prerequisite(activeConfig) ||
		configOwner.suppressFallback(activeConfig) ||
		configOwner.prerequisite(escapedConfig) ||
		configOwner.suppressFallback(escapedConfig) {
		t.Fatal("git config indirection did not distinguish fixture from live fallback")
	}
}

func TestHistoryTamperBashStyleClearGrammarIsDetectionOnly(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		command string
		want    bool
	}{
		{"history -c", true},
		{"history -a -c", true},
		{"history -ac", true},
		{"history -w -c", true},
		{"history -cw /dev/null", true},
		{"history -wc /dev/null", true},
		{"history -c | cat", false},
	} {
		test := test
		t.Run(test.command, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: test.command,
			})
			if facts.Authoritative() {
				t.Fatalf("shell-specific history grammar became authoritative: %+v", facts)
			}
			if got := historyTamperPrerequisite(facts); got != test.want {
				t.Fatalf("prerequisite=%t, want %t; facts=%+v", got, test.want, facts)
			}
		})
	}
	if contract := exactFallbackContracts["integrity.history_tamper"]; !contract.detectionOnly {
		t.Fatal("shell-specific history fallback must remain detection-only")
	}
}

func TestIntegrityOptionParsersRejectMissingOperands(t *testing.T) {
	t.Parallel()

	if unsetHistoryFileVariable(nil) {
		t.Fatal("empty unset argv was accepted")
	}
	for _, argv := range [][]string{
		{"git", "--git-dir=", "status"},
		{"git", "--git-dir", "", "status"},
	} {
		command := actionfacts.CommandFact{
			Program:      "git",
			Executable:   "git",
			Argv:         argv,
			ArgvComplete: true,
			Effect:       actionfacts.EffectExecute,
		}
		if invocation, ok := parseIntegrityGitInvocation(command); ok {
			t.Fatalf("argv=%v parsed as %+v", argv, invocation)
		}
	}
}

func TestHistoryTamperRejectsIsolatedShellContexts(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		`printf '%s\n' "$(unset HISTFILE)"`,
		`(history -c)`,
		`(unset HISTFILE)`,
		`history -c &`,
	} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:       "shell",
				Command:    command,
				CWD:        "/repo",
				ActiveHome: "/home/alice",
			})
			if facts.Authoritative() {
				t.Fatalf("isolated shell context unexpectedly authoritative: %+v", facts)
			}
			if historyTamperPrerequisite(facts) {
				t.Fatalf("isolated history mutation was owned: %+v", facts)
			}
		})
	}
}

func TestHistoryTamperRejectsExecutablePaths(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		`/usr/bin/history -c`,
		`/usr/bin/unset HISTFILE`,
	} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: command,
			})
			if facts.Authoritative() {
				t.Fatalf("shell-builtin path unexpectedly authoritative: %+v", facts)
			}
			if historyTamperPrerequisite(facts) {
				t.Fatalf("shell-builtin path was owned: %+v", facts)
			}
		})
	}
}

func TestHistoryTamperProvesDirectClearWithPartialSibling(t *testing.T) {
	t.Parallel()

	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:    "shell",
		Command: "history -c; future-command --unknown-mode",
	})
	if facts.Authoritative() {
		t.Fatalf("unknown sibling unexpectedly authoritative: %+v", facts)
	}
	if !historyTamperPrerequisite(facts) {
		t.Fatalf("direct history clear was not proven: %+v", facts)
	}
}

func TestIntegrityPersistenceMutationPathPrecision(t *testing.T) {
	tests := []struct {
		name    string
		command string
		ownerID string
		cwd     string
		home    string
		want    bool
	}{
		{"active history", "truncate -s 0 /home/alice/.bash_history", "PATH-HISTORY", "/repo", "/home/alice", true},
		{"history read", "cat /home/alice/.bash_history", "PATH-HISTORY", "/repo", "/home/alice", false},
		{"different home history read", "cat /home/bob/.bash_history", "PATH-HISTORY", "/repo", "/home/alice", false},
		{"history fixture", "truncate -s 0 /repo/testdata/.bash_history", "PATH-HISTORY", "/repo", "/home/alice", false},
		{"sudoers write", "tee /etc/sudoers", "PATH-ETC-SUDOERS", "/repo", "/home/alice", true},
		{"sudoers read", "cat /etc/sudoers", "PATH-ETC-SUDOERS", "/repo", "/home/alice", false},
		{"active profile", "printf x > /home/alice/.zshrc", "persistence.shell_profile_write", "/repo", "/home/alice", true},
		{"profile read", "cat /home/alice/.zshrc", "persistence.shell_profile_write", "/repo", "/home/alice", false},
		{"different home profile list", "ls -l /home/bob/.zshrc", "persistence.shell_profile_write", "/repo", "/home/alice", false},
		{"different home profile copy source", "cp /home/bob/.zshrc /tmp/zshrc.copy", "persistence.shell_profile_write", "/repo", "/home/alice", false},
		{"profile fixture", "printf x > /repo/fixtures/.zshrc", "persistence.shell_profile_write", "/repo", "/home/alice", false},
		{"active git hook", "printf x > .git/hooks/pre-commit", "persistence.git_hook_write", "/repo", "/home/alice", true},
		{"sample git hook", "printf x > .git/hooks/pre-commit.sample", "persistence.git_hook_write", "/repo", "/home/alice", false},
		{"fixture git hook", "printf x > testdata/project/.git/hooks/pre-commit", "persistence.git_hook_write", "/repo", "/home/alice", false},
		{"active agent config", "printf x > /home/alice/.openclaw/openclaw.json", "COG-OPENCLAW-JSON", "/repo", "/home/alice", true},
		{"unrelated agent basename", "printf x > /repo/examples/openclaw.json", "COG-OPENCLAW-JSON", "/repo", "/home/alice", false},
		{"active detector state", "truncate -s 0 /home/alice/.defenseclaw/audit.db", "tamper.detector_state_write", "/repo", "/home/alice", true},
		{"detector log excluded", "truncate -s 0 /home/alice/.defenseclaw/logs/gateway.log", "tamper.detector_state_write", "/repo", "/home/alice", false},
		{"active autostart path", "printf x > /home/alice/.config/autostart/demo.desktop", "CMD-SYSTEMCTL", "/repo", "/home/alice", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeIntegrityCommand(
				t,
				test.command,
				"",
				test.cwd,
				test.home,
			)
			owner := semanticIntegrityPersistenceOwners[test.ownerID]
			if got := owner.prerequisite(facts); got != test.want {
				t.Fatalf(
					"prerequisite = %t, want %t; facts=%+v",
					got,
					test.want,
					facts,
				)
			}
			if !test.want &&
				!owner.suppressFallback(facts) {
				t.Fatalf("definite safe negative retained fallback; facts=%+v", facts)
			}
		})
	}
}

func TestHistoryTamperDefersToActiveHistoryPathOwner(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:       "shell",
		Command:    "history -c > /home/alice/.bash_history",
		CWD:        "/repo",
		ActiveHome: "/home/alice",
	})
	if facts.Parse.Status != actionfacts.StatusPartial || facts.Authoritative() {
		t.Fatalf("shell-specific history grammar was not partial: %+v", facts)
	}
	commandOwner := semanticIntegrityPersistenceOwners["integrity.history_tamper"]
	pathOwner := semanticIntegrityPersistenceOwners["PATH-HISTORY"]
	if commandOwner.prerequisite(facts) || !pathOwner.prerequisite(facts) {
		t.Fatalf(
			"history ownership split = command:%t path:%t; facts=%+v",
			commandOwner.prerequisite(facts),
			pathOwner.prerequisite(facts),
			facts,
		)
	}
}

func TestAuthorizedKeysConditionalOwnership(t *testing.T) {
	commandOwner := semanticIntegrityPersistenceOwners["persistence.ssh_authorized_keys_command"]
	pathOwner := semanticIntegrityPersistenceOwners["PATH-SSH-DIR"]

	command := analyzeIntegrityCommand(
		t,
		"printf key >> /home/alice/.ssh/authorized_keys",
		"",
		"/repo",
		"/home/alice",
	)
	if !commandOwner.prerequisite(command) ||
		pathOwner.prerequisite(command) ||
		pathOwner.suppressFallback(command) {
		t.Fatalf(
			"command split = N23:%t H27:%t H27-safe:%t; facts=%+v",
			commandOwner.prerequisite(command),
			pathOwner.prerequisite(command),
			pathOwner.suppressFallback(command),
			command,
		)
	}

	structured := actionfacts.Analyze(actionfacts.Input{
		Tool:       "write_file",
		Args:       json.RawMessage(`{"path":"/home/alice/.ssh/authorized_keys","content":"key"}`),
		CWD:        "/repo",
		ActiveHome: "/home/alice",
	})
	requireAuthoritativeIntegrityFacts(t, structured)
	if commandOwner.prerequisite(structured) ||
		!commandOwner.suppressFallback(structured) ||
		!pathOwner.prerequisite(structured) {
		t.Fatalf(
			"structured split = N23:%t N23-safe:%t H27:%t; facts=%+v",
			commandOwner.prerequisite(structured),
			commandOwner.suppressFallback(structured),
			pathOwner.prerequisite(structured),
			structured,
		)
	}

	preview := analyzeIntegrityCommand(
		t,
		"Set-Content -Path /home/alice/.ssh/authorized_keys -Value key -WhatIf",
		actionfacts.DialectPowerShell,
		"/repo",
		"/home/alice",
	)
	if commandOwner.prerequisite(preview) ||
		pathOwner.prerequisite(preview) ||
		!commandOwner.suppressFallback(preview) ||
		!pathOwner.suppressFallback(preview) {
		t.Fatalf("preview ownership was not a safe negative: %+v", preview)
	}

	redirect := analyzeIntegrityCommand(
		t,
		"git commit --dry-run > /home/alice/.ssh/authorized_keys",
		"",
		"/repo",
		"/home/alice",
	)
	if !commandOwner.prerequisite(redirect) ||
		pathOwner.prerequisite(redirect) {
		t.Fatalf("real redirect from preview command lost N23 ownership: %+v", redirect)
	}

	unsupported := analyzeIntegrityCommand(
		t,
		"touch /home/alice/.ssh/authorized_keys",
		"",
		"/repo",
		"/home/alice",
	)
	if commandOwner.prerequisite(unsupported) ||
		pathOwner.prerequisite(unsupported) ||
		commandOwner.suppressFallback(unsupported) ||
		pathOwner.suppressFallback(unsupported) {
		t.Fatalf("unsupported mutator did not retain owner fallbacks: %+v", unsupported)
	}
}

func TestAuthorizedKeysExactFallbackDeduplicatesOnlyProvenCommandOwner(t *testing.T) {
	input := actionfacts.Input{
		Tool:       "shell",
		Command:    "printf key >> /home/alice/.ssh/authorized_keys",
		CWD:        "/repo",
		ActiveHome: "/home/alice",
	}
	findings := []RuleFinding{
		{RuleID: "persistence.ssh_authorized_keys_command"},
		{RuleID: "PATH-SSH-DIR"},
	}
	filtered := filterExactFallbackFindings(
		append([]RuleFinding(nil), findings...),
		input,
		actionfacts.Analyze(input),
		true,
	)
	if len(filtered) != 1 ||
		filtered[0].RuleID != "persistence.ssh_authorized_keys_command" {
		t.Fatalf("exact command fallback = %+v", filtered)
	}

	unsupported := input
	unsupported.Command = "touch /home/alice/.ssh/authorized_keys"
	filtered = filterExactFallbackFindings(
		append([]RuleFinding(nil), findings...),
		unsupported,
		actionfacts.Analyze(unsupported),
		true,
	)
	if len(filtered) != 1 || filtered[0].RuleID != "PATH-SSH-DIR" {
		t.Fatalf("unsupported command fallback = %+v", filtered)
	}

	filtered = filterExactFallbackFindings(
		[]RuleFinding{{RuleID: "PATH-SSH-DIR"}},
		input,
		actionfacts.Analyze(input),
		true,
	)
	if len(filtered) != 1 || filtered[0].RuleID != "PATH-SSH-DIR" {
		t.Fatalf("N23-disabled fallback = %+v", filtered)
	}
}

func TestIntegrityPersistenceEndpointPrecision(t *testing.T) {
	socketOwner := semanticIntegrityPersistenceOwners["privilege.container_runtime_socket_access"]
	socket := analyzeIntegrityCommand(
		t,
		"docker -H unix:///var/run/docker.sock ps",
		"",
		"/repo",
		"/home/alice",
	)
	if !socketOwner.prerequisite(socket) {
		t.Fatalf("runtime socket connect was not owned: %+v", socket)
	}
	socketMount := analyzeIntegrityCommand(
		t,
		"docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
		"",
		"/repo",
		"/home/alice",
	)
	if !socketOwner.prerequisite(socketMount) {
		t.Fatalf("runtime socket bind was not owned: %+v", socketMount)
	}
	rootlessDockerMount := analyzeIntegrityCommand(
		t,
		"docker run -v /run/user/1000/docker.sock:/run/docker.sock alpine",
		"",
		"/repo",
		"/home/alice",
	)
	if !socketOwner.prerequisite(rootlessDockerMount) {
		t.Fatalf("rootless docker socket bind was not owned: %+v", rootlessDockerMount)
	}
	socketRead := analyzeIntegrityCommand(
		t,
		"cat /var/run/docker.sock",
		"",
		"/repo",
		"/home/alice",
	)
	if socketOwner.prerequisite(socketRead) ||
		!socketOwner.suppressFallback(socketRead) {
		t.Fatalf("socket read was not a safe negative: %+v", socketRead)
	}

	metadataOwner := semanticIntegrityPersistenceOwners["C2-METADATA-AWS"]
	metadata := analyzeIntegrityCommand(
		t,
		"curl http://169.254.169.254/latest/meta-data/",
		"",
		"/repo",
		"/home/alice",
	)
	if !metadataOwner.prerequisite(metadata) {
		t.Fatalf("metadata fetch was not owned: %+v", metadata)
	}
	public := analyzeIntegrityCommand(
		t,
		"curl https://metadata.example.invalid/latest/",
		"",
		"/repo",
		"/home/alice",
	)
	if metadataOwner.prerequisite(public) ||
		!metadataOwner.suppressFallback(public) {
		t.Fatalf("public metadata-looking endpoint was not a safe negative: %+v", public)
	}
}

func TestCloudMetadataPrerequisiteRequiresHTTPFamily(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		scheme string
		want   bool
	}{
		{scheme: "http", want: true},
		{scheme: "HTTPS", want: true},
		{scheme: "smtp"},
		{scheme: "smtps"},
	} {
		test := test
		t.Run(test.scheme, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Facts{
				Commands: []actionfacts.CommandFact{{
					ID:         1,
					Effect:     actionfacts.EffectExecute,
					Operations: []actionfacts.OperationKind{actionfacts.OperationFetch},
				}},
				Network: []actionfacts.NetworkFact{{
					CommandID:      1,
					Action:         actionfacts.NetworkDownload,
					Scheme:         test.scheme,
					NormalizedHost: "169.254.169.254",
				}},
			}
			if got := cloudMetadataPrerequisite(facts); got != test.want {
				t.Fatalf("cloudMetadataPrerequisite(%q) = %t, want %t", test.scheme, got, test.want)
			}
		})
	}
}

func analyzeIntegrityCommand(
	t *testing.T,
	command string,
	dialect actionfacts.Dialect,
	cwd string,
	activeHome string,
) actionfacts.Facts {
	t.Helper()
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:        "shell",
		Command:     command,
		CWD:         cwd,
		ActiveHome:  activeHome,
		DialectHint: dialect,
	})
	requireAuthoritativeIntegrityFacts(t, facts)
	return facts
}

func requireAuthoritativeIntegrityFacts(
	t *testing.T,
	facts actionfacts.Facts,
) {
	t.Helper()
	if !facts.Authoritative() {
		t.Fatalf("test fixture is not authoritative: %+v", facts)
	}
}
