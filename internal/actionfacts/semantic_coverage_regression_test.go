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

import (
	"strings"
	"testing"
)

func TestSemanticCoverageStructuredPowerShellGetChildItem(t *testing.T) {
	t.Parallel()

	filesystem := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"Get-ChildItem",
			"-Path", `C:\Windows\System32`,
			"-Filter", "*.dll",
			"-File",
		},
		DialectHint: DialectPowerShell,
	})
	if !filesystem.Authoritative() ||
		!filesystem.EnforcementEligible() ||
		!factsHaveOperation(filesystem, OperationList) ||
		factsHaveOperation(filesystem, OperationEnvironmentRead) ||
		!factsHavePath(
			filesystem,
			PathAccessList,
			`C:\Windows\System32`,
		) ||
		hasPathValue(filesystem.Paths, "*.dll") {
		t.Fatalf("filesystem listing facts = %#v", filesystem)
	}

	environment := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"Get-ChildItem", "-LiteralPath", "Env:"},
		DialectHint: DialectPowerShell,
	})
	if !environment.Authoritative() ||
		!environment.EnforcementEligible() ||
		!factsHaveOperation(environment, OperationEnvironmentRead) ||
		factsHaveOperation(environment, OperationList) ||
		len(environment.Paths) != 0 {
		t.Fatalf("environment listing facts = %#v", environment)
	}

	malformed := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"Get-ChildItem",
			`C:\Windows\System32`,
			"-Filter",
		},
		DialectHint: DialectPowerShell,
	})
	if malformed.Parse.Status != StatusPartial ||
		malformed.EnforcementEligible() ||
		!factsHaveOperation(malformed, OperationList) ||
		!factsHavePath(
			malformed,
			PathAccessList,
			`C:\Windows\System32`,
		) {
		t.Fatalf("malformed listing facts = %#v", malformed)
	}

	preview := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"Get-ChildItem", "-?"},
		DialectHint: DialectPowerShell,
	})
	if !preview.Authoritative() ||
		preview.EnforcementEligible() ||
		len(preview.Commands) != 1 ||
		preview.Commands[0].Effect != EffectPreview ||
		factsHaveOperation(preview, OperationList) ||
		factsHaveOperation(preview, OperationEnvironmentRead) {
		t.Fatalf("listing preview facts = %#v", preview)
	}
}

func TestSemanticCoverageStructuredPowerShellProcessIDs(t *testing.T) {
	t.Parallel()

	valid := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"Stop-Process",
			"-Id", "12,34",
			"-Force",
		},
		DialectHint: DialectPowerShell,
	})
	if !valid.Authoritative() ||
		!valid.EnforcementEligible() ||
		!factsHaveOperation(valid, OperationProcessKill) {
		t.Fatalf("valid process ID facts = %#v", valid)
	}

	for _, ids := range []string{
		"12,,34",
		"12,fixture",
		"4294967296",
		"-1",
	} {
		ids := ids
		t.Run("invalid "+ids, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool: "exec",
				Argv: []string{
					"Stop-Process",
					"-Id", ids,
					"-Force",
				},
				DialectHint: DialectPowerShell,
			})
			if facts.Parse.Status != StatusPartial ||
				facts.EnforcementEligible() ||
				factsHaveOperation(facts, OperationProcessKill) {
				t.Fatalf("invalid process ID facts = %#v", facts)
			}
		})
	}

	missing := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"Stop-Process", "-Id"},
		DialectHint: DialectPowerShell,
	})
	if missing.Parse.Status != StatusPartial ||
		missing.EnforcementEligible() ||
		factsHaveOperation(missing, OperationProcessKill) {
		t.Fatalf("missing process ID facts = %#v", missing)
	}

	preview := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"Stop-Process",
			"-Id", "12,34",
			"-WhatIf",
		},
		DialectHint: DialectPowerShell,
	})
	if !preview.Authoritative() ||
		preview.EnforcementEligible() ||
		!factsHaveOperation(preview, OperationProcessKill) ||
		factsHaveOperation(
			preview.EnforcementProjection(),
			OperationProcessKill,
		) {
		t.Fatalf("process preview facts = %#v", preview)
	}
}

func TestSemanticCoverageRipgrepPreOptionRoles(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		{"rg", "--pre", "gzip -cd", "needle", "/srv/archive.gz"},
		{"rg", "--pre=gzip -cd", "needle", "/srv/archive.gz"},
	} {
		facts := Analyze(Input{
			Tool:        "exec",
			Argv:        argv,
			DialectHint: DialectPOSIX,
		})
		if facts.Parse.Status != StatusPartial ||
			facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationSearch) ||
			!factsHavePath(facts, PathAccessRead, "/srv/archive.gz") ||
			hasPathValue(facts.Paths, "gzip -cd") ||
			hasPathValue(facts.Paths, "needle") {
			t.Fatalf("preprocessor argv=%v facts=%#v", argv, facts)
		}
	}

	for _, argv := range [][]string{
		{"rg", "--glob", "--pre", "needle", "/srv"},
		{"rg", "--", "--pre", "/srv"},
	} {
		facts := Analyze(Input{
			Tool:        "exec",
			Argv:        argv,
			DialectHint: DialectPOSIX,
		})
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationSearch) ||
			!factsHavePath(facts, PathAccessRead, "/srv") ||
			hasPathValue(facts.Paths, "--pre") {
			t.Fatalf("literal pre option value argv=%v facts=%#v", argv, facts)
		}
	}
}

func TestSemanticCoveragePOSIXCopyMoveBundles(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		argv      []string
		operation OperationKind
		delete    bool
	}{
		{
			name:      "copy",
			argv:      []string{"cp", "-av", "/srv/source", "/srv/destination"},
			operation: OperationCopy,
		},
		{
			name:      "move",
			argv:      []string{"mv", "-fin", "/srv/source", "/srv/destination"},
			operation: OperationMove,
			delete:    true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inputs := []Input{
				{
					Tool:        "exec",
					Argv:        test.argv,
					DialectHint: DialectPOSIX,
				},
				{
					Tool:        "exec",
					Command:     posixCommandForCoverage(test.argv),
					DialectHint: DialectPOSIX,
				},
			}
			for _, input := range inputs {
				facts := Analyze(input)
				if !facts.Authoritative() ||
					!facts.EnforcementEligible() ||
					!factsHaveOperation(facts, test.operation) ||
					!factsHavePath(
						facts,
						PathAccessRead,
						"/srv/source",
					) ||
					!factsHavePath(
						facts,
						PathAccessWrite,
						"/srv/destination",
					) ||
					factsHavePath(
						facts,
						PathAccessDelete,
						"/srv/source",
					) != test.delete {
					t.Fatalf("input=%#v facts=%#v", input, facts)
				}
			}
		})
	}

	for _, test := range []struct {
		name      string
		argv      []string
		operation OperationKind
	}{
		{
			name:      "unknown copy flag",
			argv:      []string{"cp", "-az", "/srv/source", "/srv/destination"},
			operation: OperationCopy,
		},
		{
			name:      "unknown move flag",
			argv:      []string{"mv", "-a", "/srv/source", "/srv/destination"},
			operation: OperationMove,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool:        "exec",
				Argv:        test.argv,
				DialectHint: DialectPOSIX,
			})
			if facts.Parse.Status != StatusPartial ||
				facts.EnforcementEligible() ||
				!factsHaveOperation(facts, test.operation) ||
				!factsHavePath(
					facts,
					PathAccessRead,
					"/srv/source",
				) ||
				!factsHavePath(
					facts,
					PathAccessWrite,
					"/srv/destination",
				) {
				t.Fatalf("malformed bundle facts = %#v", facts)
			}
		})
	}

	optionPaths := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"cp",
			"--",
			"-source",
			"-destination",
		},
		DialectHint: DialectPOSIX,
	})
	if !optionPaths.Authoritative() ||
		!optionPaths.EnforcementEligible() ||
		!factsHavePath(optionPaths, PathAccessRead, "-source") ||
		!factsHavePath(optionPaths, PathAccessWrite, "-destination") {
		t.Fatalf("option-shaped path facts = %#v", optionPaths)
	}

	preview := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"cp", "--help"},
		DialectHint: DialectPOSIX,
	})
	if !preview.Authoritative() ||
		preview.EnforcementEligible() ||
		factsHaveOperation(preview, OperationCopy) {
		t.Fatalf("copy preview facts = %#v", preview)
	}
}

func TestSemanticCoverageSCPSwitchBundles(t *testing.T) {
	t.Parallel()

	argv := []string{
		"scp",
		"-qpr",
		"/srv/source",
		"user@relay.example:/srv/destination",
	}
	for _, input := range []Input{
		{
			Tool:        "exec",
			Argv:        argv,
			DialectHint: DialectPOSIX,
		},
		{
			Tool:        "exec",
			Command:     posixCommandForCoverage(argv),
			DialectHint: DialectPOSIX,
		},
	} {
		facts := Analyze(input)
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationUpload) ||
			!factsHaveOperation(facts, OperationConnect) ||
			!factsHavePath(facts, PathAccessRead, "/srv/source") ||
			!structuredFactsHaveNetwork(
				facts,
				NetworkUpload,
				"relay.example",
			) ||
			!structuredFactsHaveNetwork(
				facts,
				NetworkConnect,
				"relay.example",
			) {
			t.Fatalf("input=%#v facts=%#v", input, facts)
		}
	}

	malformed := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"scp",
			"-qZ",
			"/srv/source",
			"user@relay.example:/srv/destination",
		},
		DialectHint: DialectPOSIX,
	})
	if malformed.Parse.Status != StatusPartial ||
		malformed.EnforcementEligible() ||
		!factsHaveOperation(malformed, OperationUpload) ||
		!factsHavePath(malformed, PathAccessRead, "/srv/source") ||
		hasPathValue(malformed.Paths, "-qZ") {
		t.Fatalf("malformed SCP bundle facts = %#v", malformed)
	}

	optionPath := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"scp",
			"--",
			"-qpr",
			"user@relay.example:/srv/destination",
		},
		DialectHint: DialectPOSIX,
	})
	if !optionPath.Authoritative() ||
		!optionPath.EnforcementEligible() ||
		!factsHavePath(optionPath, PathAccessRead, "-qpr") ||
		!structuredFactsHaveNetwork(
			optionPath,
			NetworkUpload,
			"relay.example",
		) {
		t.Fatalf("option-shaped SCP path facts = %#v", optionPath)
	}

	preview := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"scp", "--help"},
		DialectHint: DialectPOSIX,
	})
	if !preview.Authoritative() ||
		preview.EnforcementEligible() ||
		factsHaveOperation(preview, OperationUpload) ||
		len(preview.Network) != 0 {
		t.Fatalf("SCP preview facts = %#v", preview)
	}
}

func TestSemanticCoverageCertutilDecodeHexDecimalFormat(t *testing.T) {
	t.Parallel()

	const (
		inputPath  = `C:\input.hex`
		outputPath = `C:\output.bin`
	)
	for _, input := range []Input{
		{
			Tool: "exec",
			Argv: []string{
				"certutil.exe",
				"-decodehex",
				inputPath,
				outputPath,
				"12",
			},
			DialectHint: DialectCMD,
		},
		{
			Tool: "exec",
			Command: `certutil.exe -decodehex ` +
				inputPath + " " + outputPath + " 12",
			DialectHint: DialectCMD,
		},
	} {
		facts := Analyze(input)
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationDecode) ||
			!factsHavePath(facts, PathAccessRead, inputPath) ||
			!factsHavePath(facts, PathAccessWrite, outputPath) {
			t.Fatalf("input=%#v facts=%#v", input, facts)
		}
	}

	for _, format := range []string{"0xC", "12x", "-1", "+1"} {
		format := format
		t.Run("invalid "+format, func(t *testing.T) {
			t.Parallel()

			for _, input := range []Input{
				{
					Tool: "exec",
					Argv: []string{
						"certutil.exe",
						"-decodehex",
						inputPath,
						outputPath,
						format,
					},
					DialectHint: DialectCMD,
				},
				{
					Tool: "exec",
					Command: `certutil.exe -decodehex ` +
						inputPath + " " + outputPath + " " + format,
					DialectHint: DialectCMD,
				},
			} {
				facts := Analyze(input)
				if facts.Parse.Status != StatusPartial ||
					facts.EnforcementEligible() {
					t.Fatalf("input=%#v facts=%#v", input, facts)
				}
			}
		})
	}

	encode := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"certutil.exe",
			"-encodehex",
			inputPath,
			outputPath,
			"12",
		},
		DialectHint: DialectCMD,
	})
	if factsHaveOperation(encode, OperationDecode) ||
		factsHavePath(encode, PathAccessRead, inputPath) ||
		factsHavePath(encode, PathAccessWrite, outputPath) {
		t.Fatalf("encode facts = %#v", encode)
	}
}

func TestSemanticCoverageBase64DecodeBundlesStayCrossPlatform(t *testing.T) {
	t.Parallel()

	for _, bundle := range []string{"-di", "-id", "-Di", "-dd", "-dD"} {
		bundle := bundle
		t.Run(bundle, func(t *testing.T) {
			t.Parallel()

			for _, input := range []Input{
				{
					Tool: "exec",
					Argv: []string{
						"base64",
						bundle,
						"/srv/payload.b64",
					},
					DialectHint: DialectPOSIX,
				},
				{
					Tool: "exec",
					Command: "base64 " + bundle +
						" /srv/payload.b64",
					DialectHint: DialectPOSIX,
				},
			} {
				facts := Analyze(input)
				if facts.Parse.Status != StatusPartial ||
					facts.EnforcementEligible() ||
					!factsHaveOperation(facts, OperationDecode) ||
					!factsHavePath(
						facts,
						PathAccessRead,
						"/srv/payload.b64",
					) {
					t.Fatalf(
						"ambiguous bundle input=%#v facts=%#v",
						input,
						facts,
					)
				}
			}
		})
	}

	unambiguous := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"base64", "-d", "/srv/payload.b64"},
		DialectHint: DialectPOSIX,
	})
	if !unambiguous.Authoritative() ||
		!unambiguous.EnforcementEligible() ||
		!factsHaveOperation(unambiguous, OperationDecode) ||
		!factsHavePath(
			unambiguous,
			PathAccessRead,
			"/srv/payload.b64",
		) {
		t.Fatalf("unambiguous decode bundle facts=%#v", unambiguous)
	}

	for _, option := range []string{"-ix", "-i", "--decode-extra"} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{
				"base64",
				option,
				"/srv/payload.b64",
			},
			DialectHint: DialectPOSIX,
		})
		if factsHaveOperation(facts, OperationDecode) {
			t.Fatalf(
				"non-decode option %q minted decode facts: %#v",
				option,
				facts,
			)
		}
	}
}

func TestSemanticCoverageNetAccountsGrammar(t *testing.T) {
	t.Parallel()

	for _, option := range []string{
		"/forcelogoff:30",
		"/minpwlen:14",
		"/maxpwage:90",
		"/minpwage:1",
		"/uniquepw:24",
	} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{
				"net.exe",
				"accounts",
				option,
			},
			DialectHint: DialectCMD,
		})
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationAccountChange) ||
			factsHaveOperation(facts, OperationList) {
			t.Fatalf("option=%q facts=%#v", option, facts)
		}
	}

	for _, argv := range [][]string{
		{"net.exe", "accounts"},
		{"net.exe", "accounts", "/domain"},
	} {
		facts := Analyze(Input{
			Tool:        "exec",
			Argv:        argv,
			DialectHint: DialectCMD,
		})
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			factsHaveOperation(facts, OperationAccountChange) ||
			!factsHaveOperation(facts, OperationList) {
			t.Fatalf("query argv=%v facts=%#v", argv, facts)
		}
	}

	for _, option := range []string{
		"/future:fixture",
		"/minpwlen:",
		"/maxpwage:never",
		"/uniquepw:-1",
	} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{
				"net.exe",
				"accounts",
				option,
			},
			DialectHint: DialectCMD,
		})
		if facts.Parse.Status != StatusPartial ||
			facts.EnforcementEligible() {
			t.Fatalf("option=%q facts=%#v", option, facts)
		}
	}

	preview := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"net.exe",
			"accounts",
			"/?",
		},
		DialectHint: DialectCMD,
	})
	if !preview.Authoritative() ||
		preview.EnforcementEligible() ||
		len(preview.Commands) != 1 ||
		preview.Commands[0].Effect != EffectPreview ||
		factsHaveOperation(preview, OperationAccountChange) {
		t.Fatalf("accounts preview facts = %#v", preview)
	}
}

func TestSemanticCoverageNetworkRangeScope(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		target     string
		normalized string
		scope      NetworkScope
		kind       NetworkTargetKind
	}{
		{
			name:       "public",
			target:     "8.0.0.0-9.0.0.0",
			normalized: "8.0.0.0-9.0.0.0",
			scope:      NetworkScopePublic,
			kind:       NetworkTargetRange,
		},
		{
			name:       "crosses private",
			target:     "9.255.255.255-11.0.0.0",
			normalized: "9.255.255.255-11.0.0.0",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetRange,
		},
		{
			name:       "private",
			target:     "10.0.0.1-10.0.0.10",
			normalized: "10.0.0.1-10.0.0.10",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetRange,
		},
		{
			name:   "reversed",
			target: "11.0.0.0-9.255.255.255",
			scope:  NetworkScopeUnknown,
			kind:   NetworkTargetUnknown,
		},
		{
			name:   "mixed family",
			target: "8.0.0.0-2001:4860::1",
			scope:  NetworkScopeUnknown,
			kind:   NetworkTargetUnknown,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			normalized, scope, kind, prefix := deriveNetworkTarget(
				test.target,
			)
			if normalized != test.normalized ||
				scope != test.scope ||
				kind != test.kind ||
				prefix != 0 {
				t.Fatalf(
					"deriveNetworkTarget(%q) = (%q, %q, %q, %d)",
					test.target,
					normalized,
					scope,
					kind,
					prefix,
				)
			}
		})
	}

	const crossing = "9.255.255.255-11.0.0.0"
	for _, input := range []Input{
		{
			Tool:        "exec",
			Argv:        []string{"nmap", "-sn", crossing},
			DialectHint: DialectPOSIX,
		},
		{
			Tool:        "exec",
			Command:     "nmap -sn " + crossing,
			DialectHint: DialectPOSIX,
		},
	} {
		facts := Analyze(input)
		if !facts.Authoritative() ||
			!facts.EnforcementEligible() ||
			!factsHaveOperation(facts, OperationNetworkScan) ||
			!semanticCoverageHasNetworkRange(
				facts,
				NetworkScan,
				crossing,
				NetworkScopeUnknown,
			) {
			t.Fatalf("input=%#v facts=%#v", input, facts)
		}
	}
}

func TestSemanticCoverageWindowsPositiveCounts(t *testing.T) {
	t.Parallel()

	valid := Analyze(Input{
		Tool: "exec",
		Command: `naabu.exe --host 192.0.2.7 ` +
			`--rate 5`,
		DialectHint: DialectCMD,
	})
	if !valid.Authoritative() ||
		!valid.EnforcementEligible() ||
		!factsHaveOperation(valid, OperationNetworkScan) ||
		!structuredFactsHaveNetwork(valid, NetworkScan, "192.0.2.7") {
		t.Fatalf("valid count facts = %#v", valid)
	}

	for _, rate := range []string{
		"0",
		"-1",
		"fixture",
		"2147483648",
	} {
		rate := rate
		t.Run("invalid "+rate, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool: "exec",
				Command: `naabu.exe --host 192.0.2.7 ` +
					`--rate ` + rate,
				DialectHint: DialectCMD,
			})
			if facts.Parse.Status != StatusPartial ||
				facts.EnforcementEligible() ||
				factsHaveOperation(facts, OperationNetworkScan) ||
				len(facts.Network) != 0 {
				t.Fatalf("invalid count facts = %#v", facts)
			}
		})
	}

	missing := Analyze(Input{
		Tool:        "exec",
		Command:     `naabu.exe --host 192.0.2.7 --rate`,
		DialectHint: DialectCMD,
	})
	if missing.Parse.Status != StatusPartial ||
		missing.EnforcementEligible() ||
		factsHaveOperation(missing, OperationNetworkScan) ||
		len(missing.Network) != 0 {
		t.Fatalf("missing count facts = %#v", missing)
	}
}

func posixCommandForCoverage(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	command := argv[0]
	for _, arg := range argv[1:] {
		command += " '" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
	}
	return command
}

func TestPOSIXCommandForCoverageEscapesSingleQuotes(t *testing.T) {
	t.Parallel()

	const want = "fixture's value"
	out := parsePOSIX(
		posixCommandForCoverage([]string{"printf", "%s", want}),
		1,
		0,
	)
	if out.status != StatusComplete || len(out.commands) != 1 ||
		len(out.commands[0].Argv) != 3 ||
		out.commands[0].Argv[2] != want {
		t.Fatalf("quote-bearing coverage command parsed incorrectly: %#v", out)
	}
}

func semanticCoverageHasNetworkRange(
	facts Facts,
	action NetworkAction,
	host string,
	scope NetworkScope,
) bool {
	for _, fact := range facts.Network {
		if fact.Action == action &&
			fact.Host == host &&
			fact.NormalizedHost == host &&
			fact.Scope == scope &&
			fact.TargetKind == NetworkTargetRange {
			return true
		}
	}
	return false
}
