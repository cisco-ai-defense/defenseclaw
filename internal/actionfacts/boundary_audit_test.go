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

package actionfacts

import "testing"

func TestStructuredWindowsPathPatternsRemainFallbackOnly(t *testing.T) {
	tests := []struct {
		name       string
		dialect    Dialect
		raw        string
		argv       []string
		operation  OperationKind
		pathAccess PathAccess
	}{
		{
			name:       "PowerShell copy wildcard",
			dialect:    DialectPowerShell,
			raw:        `Copy-Item C:\secrets\*.txt C:\staging`,
			argv:       []string{"Copy-Item", `C:\secrets\*.txt`, `C:\staging`},
			operation:  OperationCopy,
			pathAccess: PathAccessRead,
		},
		{
			name:       "PowerShell alias move character class",
			dialect:    DialectPowerShell,
			raw:        `mv C:\secrets\[ab].txt C:\staging`,
			argv:       []string{"mv", `C:\secrets\[ab].txt`, `C:\staging`},
			operation:  OperationMove,
			pathAccess: PathAccessRead,
		},
		{
			name:       "CMD delete wildcard",
			dialect:    DialectCMD,
			raw:        `del C:\secrets\*.txt`,
			argv:       []string{"del", `C:\secrets\*.txt`},
			operation:  OperationDelete,
			pathAccess: PathAccessDelete,
		},
		{
			name:       "CMD read single-character wildcard",
			dialect:    DialectCMD,
			raw:        `type C:\secrets\?.txt`,
			argv:       []string{"type", `C:\secrets\?.txt`},
			operation:  OperationRead,
			pathAccess: PathAccessRead,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, structured := boundaryWindowsAnalyzePair(
				test.dialect,
				test.raw,
				test.argv,
			)
			for name, facts := range map[string]Facts{
				"raw": raw, "structured": structured,
			} {
				if facts.Authoritative() ||
					facts.Parse.Status != StatusPartial ||
					facts.EnforcementEligible() ||
					!containsIssue(facts.Parse.Issues, IssueDynamicWord) {
					t.Fatalf("%s facts became authoritative: %#v", name, facts)
				}
				if len(facts.Commands) != 1 ||
					!commandHasOperation(facts.Commands[0], test.operation) {
					t.Fatalf("%s lost detection operation: %#v", name, facts)
				}
				for _, path := range facts.Paths {
					if path.Access == test.pathAccess &&
						path.Resolved != "" {
						t.Fatalf(
							"%s pattern became an exact resolved path: %#v",
							name,
							facts,
						)
					}
				}
			}
		})
	}
}

func boundaryWindowsAnalyzePair(
	dialect Dialect,
	raw string,
	argv []string,
) (Facts, Facts) {
	return Analyze(Input{
			Tool:        "exec_command",
			Command:     raw,
			DialectHint: dialect,
		}), Analyze(Input{
			Tool:        "exec_command",
			Argv:        argv,
			DialectHint: dialect,
		})
}

func TestWindowsCurlRepeatedProxyKeepsOnlyEffectivePeer(t *testing.T) {
	facts := Analyze(Input{
		Tool: "exec_command",
		Command: `curl.exe -x http://stale.example:8080 ` +
			`-x http://effective.example:8081 https://destination.example/a`,
		DialectHint: DialectCMD,
	})

	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		len(facts.Commands) != 1 ||
		!commandHasOperation(facts.Commands[0], OperationFetch) {
		t.Fatalf("facts = %#v", facts)
	}
	if hasNetworkHost(facts, NetworkConnect, "stale.example") ||
		!hasNetworkHost(facts, NetworkConnect, "effective.example") ||
		!hasNetworkHost(facts, NetworkDownload, "destination.example") {
		t.Fatalf("proxy selection facts = %#v", facts.Network)
	}
}

func TestAtHelpLikeFileOperandDoesNotSuppressSchedule(t *testing.T) {
	for name, input := range map[string]Input{
		"raw": {
			Tool:        "exec_command",
			Command:     "at -f --help now",
			DialectHint: DialectPOSIX,
		},
		"structured": {
			Tool:        "exec_command",
			Argv:        []string{"at", "-f", "--help", "now"},
			DialectHint: DialectPOSIX,
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(input)
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectExecute ||
				!commandHasOperation(
					facts.Commands[0],
					OperationSchedule,
				) ||
				commandHasOperation(facts.Commands[0], OperationList) ||
				!factsHavePath(facts, PathAccessRead, "--help") {
				t.Fatalf("help-like file suppressed scheduling: %#v", facts)
			}
		})
	}

	help := Analyze(Input{
		Tool:        "exec_command",
		Argv:        []string{"at", "--help"},
		DialectHint: DialectPOSIX,
	})
	if !help.Authoritative() || len(help.Commands) != 1 ||
		help.Commands[0].Effect != EffectPreview ||
		commandHasOperation(help.Commands[0], OperationSchedule) ||
		len(help.EnforcementProjection().Commands) != 0 {
		t.Fatalf("actual help was not a pure preview: %#v", help)
	}
}

func TestTeeControlsRespectOptionTerminationAndBundles(t *testing.T) {
	overwrite := Analyze(Input{
		Tool: "exec_command",
		Argv: []string{"tee", "--", "--append"},
	})
	if !overwrite.Authoritative() || !overwrite.EnforcementEligible() ||
		len(overwrite.Commands) != 1 ||
		!commandHasOperation(overwrite.Commands[0], OperationWrite) ||
		commandHasOperation(overwrite.Commands[0], OperationAppend) ||
		!factsHavePath(overwrite, PathAccessWrite, "--append") ||
		factsHavePath(overwrite, PathAccessAppend, "--append") {
		t.Fatalf("terminated operand became append control: %#v", overwrite)
	}

	appendBundle := Analyze(Input{
		Tool: "exec_command",
		Argv: []string{"tee", "-ai", "/tmp/audit.log"},
	})
	if !appendBundle.Authoritative() || !appendBundle.EnforcementEligible() ||
		len(appendBundle.Commands) != 1 ||
		!commandHasOperation(appendBundle.Commands[0], OperationAppend) ||
		!factsHavePath(
			appendBundle,
			PathAccessAppend,
			"/tmp/audit.log",
		) {
		t.Fatalf("owned short bundle lost append semantics: %#v", appendBundle)
	}

	help := Analyze(Input{
		Tool: "exec_command",
		Argv: []string{"tee", "--help"},
	})
	if !help.Authoritative() || len(help.Commands) != 1 ||
		help.Commands[0].Effect != EffectPreview ||
		commandHasOperation(help.Commands[0], OperationWrite) ||
		len(help.EnforcementProjection().Commands) != 0 {
		t.Fatalf("tee help became an executing write: %#v", help)
	}
}

func TestInformationalMutatorsArePreviewOnly(t *testing.T) {
	tests := []Input{
		{
			Tool:        "exec_command",
			Argv:        []string{"unlink", "--help"},
			DialectHint: DialectPOSIX,
		},
		{
			Tool:        "exec_command",
			Command:     `del /? C:\victim.txt`,
			DialectHint: DialectCMD,
		},
		{
			Tool:        "exec_command",
			Argv:        []string{"del", "/?", `C:\victim.txt`},
			DialectHint: DialectCMD,
		},
	}
	for _, input := range tests {
		facts := Analyze(input)
		if !facts.Authoritative() || len(facts.Commands) != 1 ||
			facts.Commands[0].Effect != EffectPreview ||
			facts.EnforcementEligible() ||
			len(facts.EnforcementProjection().Commands) != 0 {
			t.Fatalf("informational mutation enforced: %#v", facts)
		}
	}
}

func hasNetworkHost(facts Facts, action NetworkAction, host string) bool {
	for _, fact := range facts.Network {
		if fact.Action == action && fact.NormalizedHost == host {
			return true
		}
	}
	return false
}
