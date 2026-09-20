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
	"encoding/json"
	"testing"
)

func TestStructuredPowerShellPathMutatorRolesAndControls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		argv       []string
		wantStatus ParseStatus
		wantEffect CommandEffect
		wantOp     OperationKind
		wantPaths  map[PathAccess]string
	}{
		{
			name: "set content named value is data",
			argv: []string{
				"Set-Content", "-Value", `C:\not-a-path`,
				"-LiteralPath", `C:\target.txt`,
			},
			wantStatus: StatusComplete,
			wantEffect: EffectExecute,
			wantOp:     OperationWrite,
			wantPaths:  map[PathAccess]string{PathAccessWrite: `C:\target.txt`},
		},
		{
			name: "out file input object is data",
			argv: []string{
				"Out-File", "-InputObject", `C:\not-a-path`,
				"-FilePath", `C:\target.txt`,
			},
			wantStatus: StatusComplete,
			wantEffect: EffectExecute,
			wantOp:     OperationWrite,
			wantPaths:  map[PathAccess]string{PathAccessWrite: `C:\target.txt`},
		},
		{
			name: "copy named roles",
			argv: []string{
				"Copy-Item", "-Destination", `C:\dst.txt`,
				"-LiteralPath", `C:\src.txt`,
			},
			wantStatus: StatusComplete,
			wantEffect: EffectExecute,
			wantOp:     OperationCopy,
			wantPaths: map[PathAccess]string{
				PathAccessRead: `C:\src.txt`, PathAccessWrite: `C:\dst.txt`,
			},
		},
		{
			name:       "remove whatif preserves detection semantics",
			argv:       []string{"Remove-Item", "-LiteralPath", `C:\victim`, "-WhatIf"},
			wantStatus: StatusComplete,
			wantEffect: EffectPreview,
			wantOp:     OperationDelete,
			wantPaths:  map[PathAccess]string{PathAccessDelete: `C:\victim`},
		},
		{
			name:       "conflicting named paths are partial",
			argv:       []string{"Set-Content", "-Path", `C:\a`, "-LiteralPath", `C:\b`, "-Value", "x"},
			wantStatus: StatusPartial,
			wantEffect: EffectExecute,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Argv: test.argv, DialectHint: DialectPowerShell})
			if facts.Parse.Status != test.wantStatus ||
				len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != test.wantEffect {
				t.Fatalf("facts = %#v", facts)
			}
			if test.wantOp != "" &&
				!commandHasOperation(facts.Commands[0], test.wantOp) {
				t.Fatalf("operations = %v", facts.Commands[0].Operations)
			}
			for access, value := range test.wantPaths {
				if !factsHavePath(facts, access, value) {
					t.Fatalf("paths = %#v, want %s %q", facts.Paths, access, value)
				}
			}
			if len(test.wantPaths) != len(facts.Paths) {
				t.Fatalf("paths = %#v", facts.Paths)
			}
		})
	}
}

func TestStructuredPowerShellPathMutatorBooleanSwitches(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		argv      []string
		operation OperationKind
		access    PathAccess
		path      string
	}{
		{
			name: "no newline true",
			argv: []string{
				"Set-Content", "-LiteralPath", `C:\target.txt`,
				"-Value", "fixture", "-NoNewline:$true",
			},
			operation: OperationWrite,
			access:    PathAccessWrite,
			path:      `C:\target.txt`,
		},
		{
			name: "append false remains overwrite",
			argv: []string{
				"Out-File", "-FilePath", `C:\target.txt`,
				"-InputObject", "fixture", "-Append:$false",
			},
			operation: OperationWrite,
			access:    PathAccessWrite,
			path:      `C:\target.txt`,
		},
		{
			name: "append true retains append semantics",
			argv: []string{
				"Out-File", "-FilePath", `C:\target.txt`,
				"-InputObject", "fixture", "-Append:$true",
			},
			operation: OperationAppend,
			access:    PathAccessAppend,
			path:      `C:\target.txt`,
		},
		{
			name: "pass thru true",
			argv: []string{
				"Copy-Item", "-LiteralPath", `C:\source.txt`,
				"-Destination", `C:\target.txt`, "-PassThru:$true",
			},
			operation: OperationCopy,
			access:    PathAccessWrite,
			path:      `C:\target.txt`,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Argv: test.argv, DialectHint: DialectPowerShell,
			})
			if !facts.Authoritative() || len(facts.Commands) != 1 ||
				!commandHasOperation(facts.Commands[0], test.operation) ||
				!factsHavePath(facts, test.access, test.path) {
				t.Fatalf("facts = %#v", facts)
			}
			if test.name == "append false remains overwrite" &&
				(commandHasOperation(facts.Commands[0], OperationAppend) ||
					factsHavePath(facts, PathAccessAppend, test.path)) {
				t.Fatalf("false append switch acted enabled: %#v", facts)
			}
		})
	}

	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "no newline invalid",
			argv: []string{
				"Set-Content", "-LiteralPath", `C:\target.txt`,
				"-Value", "fixture", "-NoNewline:maybe",
			},
		},
		{
			name: "append empty",
			argv: []string{
				"Out-File", "-FilePath", `C:\target.txt`,
				"-InputObject", "fixture", "-Append:",
			},
		},
		{
			name: "pass thru invalid",
			argv: []string{
				"Copy-Item", "-LiteralPath", `C:\source.txt`,
				"-Destination", `C:\target.txt`, "-PassThru:2",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Argv:        test.argv,
				DialectHint: DialectPowerShell,
			})
			if facts.Authoritative() ||
				!containsIssue(facts.Parse.Issues, IssueUnknownOperandGrammar) {
				t.Fatalf("malformed switch became authoritative: %#v", facts)
			}
		})
	}
}

func TestPowerShellPathMutatorRawStructuredParity(t *testing.T) {
	t.Parallel()
	raw := Analyze(Input{
		Tool:    "powershell",
		Command: `Set-Content -Value literal -Path 'C:\target.txt' -WhatIf`,
	})
	structured := Analyze(Input{
		Argv:        []string{"Set-Content", "-Value", "literal", "-Path", `C:\target.txt`, "-WhatIf"},
		DialectHint: DialectPowerShell,
	})
	if raw.Parse.Status != StatusComplete ||
		structured.Parse.Status != StatusComplete ||
		len(raw.Commands) != 1 || len(structured.Commands) != 1 ||
		raw.Commands[0].Effect != EffectPreview ||
		structured.Commands[0].Effect != EffectPreview ||
		len(raw.Paths) != 1 || len(structured.Paths) != 1 ||
		raw.Paths[0].Access != structured.Paths[0].Access ||
		raw.Paths[0].Normalized != structured.Paths[0].Normalized {
		t.Fatalf("raw=%#v structured=%#v", raw, structured)
	}
}

func TestStructuredPowerShellDeleteAliasWhatIf(t *testing.T) {
	t.Parallel()
	for _, alias := range []string{"del", "erase", "rd", "rmdir", "rm"} {
		alias := alias
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			raw := Analyze(Input{
				Tool:    "powershell",
				Command: alias + ` C:\victim`,
			})
			structured := Analyze(Input{
				Argv:        []string{alias, `C:\victim`},
				DialectHint: DialectPowerShell,
			})
			for name, facts := range map[string]Facts{
				"raw": raw, "structured": structured,
			} {
				if facts.Parse.Status != StatusComplete ||
					!commandHasOperation(facts.Commands[0], OperationDelete) ||
					!factsHavePath(facts, PathAccessDelete, `C:\victim`) {
					t.Fatalf("%s = %#v", name, facts)
				}
			}
			preview := Analyze(Input{
				Argv:        []string{alias, `C:\victim`, "-WhatIf:$true"},
				DialectHint: DialectPowerShell,
			})
			if preview.Parse.Status != StatusComplete ||
				preview.Commands[0].Effect != EffectPreview ||
				!commandHasOperation(preview.Commands[0], OperationDelete) ||
				!factsHavePath(preview, PathAccessDelete, `C:\victim`) {
				t.Fatalf("preview = %#v", preview)
			}
			execute := Analyze(Input{
				Argv:        []string{alias, `C:\victim`, "-WhatIf:$false"},
				DialectHint: DialectPowerShell,
			})
			if execute.Parse.Status != StatusComplete ||
				execute.Commands[0].Effect != EffectExecute ||
				!commandHasOperation(execute.Commands[0], OperationDelete) {
				t.Fatalf("execute = %#v", execute)
			}
			conflict := Analyze(Input{
				Argv: []string{
					alias, `C:\victim`, "-WhatIf:$true", "-WhatIf:$false",
				},
				DialectHint: DialectPowerShell,
			})
			if conflict.Parse.Status != StatusPartial ||
				conflict.Commands[0].Effect != EffectUncertain ||
				commandHasOperation(conflict.Commands[0], OperationDelete) {
				t.Fatalf("conflict = %#v", conflict)
			}
		})
	}
}

func TestPowerShellCopyMoveAliasesRawStructuredAndWhatIf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		alias     string
		operation OperationKind
		source    string
		target    string
	}{
		{"cp", OperationCopy, `C:\src.txt`, `C:\dst.txt`},
		{"mv", OperationMove, `C:\src.txt`, `C:\dst.txt`},
		{"rni", OperationMove, `C:\src.txt`, `C:\renamed.txt`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.alias, func(t *testing.T) {
			t.Parallel()
			raw := Analyze(Input{
				Tool: "powershell",
				Command: test.alias + ` ` + test.source + ` ` +
					test.target,
			})
			structured := Analyze(Input{
				Argv:        []string{test.alias, test.source, test.target},
				DialectHint: DialectPowerShell,
			})
			for name, facts := range map[string]Facts{
				"raw": raw, "structured": structured,
			} {
				if facts.Parse.Status != StatusComplete ||
					len(facts.Commands) != 1 ||
					!commandHasOperation(facts.Commands[0], test.operation) ||
					!factsHavePath(facts, PathAccessRead, test.source) ||
					!factsHavePath(facts, PathAccessWrite, test.target) {
					t.Fatalf("%s = %#v", name, facts)
				}
				if test.operation == OperationMove &&
					!factsHavePath(facts, PathAccessDelete, test.source) {
					t.Fatalf("%s move roles = %#v", name, facts.Paths)
				}
			}

			preview := Analyze(Input{
				Argv: []string{
					test.alias, test.source, test.target, "-WhatIf:$true",
				},
				DialectHint: DialectPowerShell,
			})
			if preview.Parse.Status != StatusComplete ||
				preview.Commands[0].Effect != EffectPreview ||
				!commandHasOperation(preview.Commands[0], test.operation) {
				t.Fatalf("preview = %#v", preview)
			}
			execute := Analyze(Input{
				Argv: []string{
					test.alias, test.source, test.target, "-WhatIf:$false",
				},
				DialectHint: DialectPowerShell,
			})
			if execute.Parse.Status != StatusComplete ||
				execute.Commands[0].Effect != EffectExecute ||
				!commandHasOperation(execute.Commands[0], test.operation) {
				t.Fatalf("execute = %#v", execute)
			}
			conflict := Analyze(Input{
				Argv: []string{
					test.alias, test.source, test.target,
					"-WhatIf:$true", "-WhatIf:$false",
				},
				DialectHint: DialectPowerShell,
			})
			if conflict.Parse.Status != StatusPartial ||
				conflict.Commands[0].Effect != EffectUncertain ||
				commandHasOperation(conflict.Commands[0], test.operation) {
				t.Fatalf("conflict = %#v", conflict)
			}
		})
	}
}

func TestRegistryCanonicalizationAndValueControls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		command    string
		wantStatus ParseStatus
		wantPath   string
	}{
		{
			name: "provider alias Run key",
			command: `Set-ItemProperty -Path ` +
				`'Microsoft.PowerShell.Core\Registry::HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' ` +
				`-Name Updater -Value 'C:\payload.exe'`,
			wantStatus: StatusComplete,
			wantPath:   "HKCU/Software/Microsoft/Windows/CurrentVersion/Run",
		},
		{
			name: "reg add RunOnce key",
			command: `reg add ` +
				`"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" ` +
				`/v Updater /t REG_SZ /d "C:\payload.exe" /f`,
			wantStatus: StatusComplete,
			wantPath:   "HKCU/Software/Microsoft/Windows/CurrentVersion/RunOnce",
		},
		{
			name:       "malformed provider alias is partial",
			command:    `Set-ItemProperty -Path 'Registry::HKCU:\Software\*\Run' -Name Updater -Value x`,
			wantStatus: StatusPartial,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "powershell", Command: test.command})
			if facts.Parse.Status != test.wantStatus {
				t.Fatalf("facts = %#v", facts)
			}
			if test.wantPath == "" {
				if len(facts.Paths) != 0 {
					t.Fatalf("unsafe registry path = %#v", facts.Paths)
				}
				return
			}
			if len(facts.Paths) != 1 ||
				facts.Paths[0].Flavor != PathFlavorRegistry ||
				facts.Paths[0].Normalized != test.wantPath ||
				facts.Paths[0].Resolved != test.wantPath {
				t.Fatalf("paths = %#v", facts.Paths)
			}
			for _, path := range facts.Paths {
				if path.Value == `C:\payload.exe` {
					t.Fatalf("registry data value became a path: %#v", facts.Paths)
				}
			}
		})
	}
}

func TestGitRemoteEndpointsAndQueries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		argv        []string
		wantStatus  ParseStatus
		wantScheme  string
		wantHost    string
		wantNetwork int
		wantConfig  bool
	}{
		{
			name: "https add", argv: []string{
				"git", "remote", "add", "origin", "https://Example.TEST/org/repo.git",
			},
			wantStatus: StatusComplete, wantScheme: "https",
			wantHost: "example.test", wantNetwork: 1, wantConfig: true,
		},
		{
			name: "ssh set url", argv: []string{
				"git", "remote", "set-url", "origin", "ssh://git@example.test:2222/org/repo.git",
			},
			wantStatus: StatusComplete, wantScheme: "ssh",
			wantHost: "example.test", wantNetwork: 1, wantConfig: true,
		},
		{
			name: "scp like add", argv: []string{
				"git", "remote", "add", "origin", "git@example.test:org/repo.git",
			},
			wantStatus: StatusComplete, wantScheme: "ssh",
			wantHost: "example.test", wantNetwork: 1, wantConfig: true,
		},
		{
			name:       "remote query quiet",
			argv:       []string{"git", "remote", "get-url", "origin"},
			wantStatus: StatusComplete,
		},
		{
			name:       "remote verbose listing quiet",
			argv:       []string{"git", "remote", "-v"},
			wantStatus: StatusComplete,
		},
		{
			name: "extra add operand partial",
			argv: []string{
				"git", "remote", "add", "origin", "https://example.test/repo.git", "extra",
			},
			wantStatus: StatusPartial, wantConfig: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Argv: test.argv})
			if facts.Parse.Status != test.wantStatus ||
				len(facts.Network) != test.wantNetwork ||
				len(facts.Commands) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			if test.wantNetwork != 0 &&
				(facts.Network[0].Action != NetworkConnect ||
					facts.Network[0].Scheme != test.wantScheme ||
					facts.Network[0].Host != test.wantHost) {
				t.Fatalf("network = %#v", facts.Network)
			}
			hasConfig := commandHasOperation(facts.Commands[0], OperationConfigChange)
			if hasConfig != test.wantConfig {
				t.Fatalf("operations = %#v", facts.Commands[0].Operations)
			}
		})
	}
}

func TestGitRemoteRawWindowsParity(t *testing.T) {
	t.Parallel()
	raw := Analyze(Input{
		Tool:    "powershell",
		Command: `git.exe remote add origin https://Example.TEST/org/repo.git`,
	})
	structured := Analyze(Input{
		Argv:        []string{"git.exe", "remote", "add", "origin", "https://Example.TEST/org/repo.git"},
		DialectHint: DialectPowerShell,
	})
	if raw.Parse.Status != StatusComplete ||
		structured.Parse.Status != StatusComplete ||
		len(raw.Network) != 1 || len(structured.Network) != 1 ||
		raw.Network[0].Host != structured.Network[0].Host ||
		raw.Network[0].Scheme != structured.Network[0].Scheme {
		t.Fatalf("raw=%#v structured=%#v", raw, structured)
	}
}

func TestSudoTerminalAndShellSemantics(t *testing.T) {
	t.Parallel()
	for _, argv := range [][]string{
		{"sudo", "-l"},
		{"sudo", "-s"},
		{"sudo", "-i"},
		{"sudo", "/bin/sh"},
	} {
		facts := Analyze(Input{Argv: argv, DialectHint: DialectPOSIX})
		if facts.Parse.Status != StatusComplete || len(facts.Commands) != 1 ||
			!commandHasOperation(facts.Commands[0], OperationPrivilege) {
			t.Fatalf("%v = %#v", argv, facts)
		}
	}
	opaque := Analyze(Input{
		Argv:        []string{"sudo", "/bin/sh", "-c", "rm -rf /tmp/fixture"},
		DialectHint: DialectPOSIX,
	})
	if opaque.Parse.Status != StatusPartial {
		t.Fatalf("opaque shell = %#v", opaque)
	}
}

func TestContainerMountDestinationsAreExact(t *testing.T) {
	t.Parallel()
	valid := Analyze(Input{Argv: []string{
		"docker", "run", "--mount",
		"type=bind,source=/srv/data,target=/data,readonly",
		"alpine",
	}})
	if valid.Parse.Status != StatusComplete ||
		!factsHavePath(valid, PathAccessRead, "/srv/data") ||
		factsHavePath(valid, PathAccessWrite, "/srv/data") {
		t.Fatalf("valid mount = %#v", valid)
	}
	hostRoot := Analyze(Input{
		Argv: []string{"docker", "run", "-v", "/:/", "alpine"},
	})
	if hostRoot.Parse.Status != StatusComplete ||
		!factsHavePath(hostRoot, PathAccessRead, "/") ||
		!factsHavePath(hostRoot, PathAccessWrite, "/") {
		t.Fatalf("host root mount = %#v", hostRoot)
	}
	for _, mount := range []string{
		"/srv/data:relative",
		"/srv/data:",
		"/srv/data:/data:ro:extra",
		"type=bind,source=/srv/data,target=relative",
		"type=bind,source=/srv/data,src=/other,target=/data",
	} {
		facts := Analyze(Input{Argv: []string{"docker", "run", "-v", mount, "alpine"}})
		if facts.Parse.Status != StatusPartial || len(facts.Paths) != 0 {
			t.Fatalf("%q = %#v", mount, facts)
		}
	}
}

func TestRepeatedValueOptionsAndGpasswd(t *testing.T) {
	t.Parallel()
	repeated := Analyze(Input{Argv: []string{
		"useradd", "-d", "/home/one", "-d", "/home/two", "fixture",
	}})
	if repeated.Parse.Status != StatusPartial {
		t.Fatalf("repeated option = %#v", repeated)
	}
	exact := Analyze(Input{Argv: []string{"gpasswd", "-a", "fixture", "wheel"}})
	if exact.Parse.Status != StatusComplete ||
		len(exact.Commands) != 1 ||
		!commandHasOperation(exact.Commands[0], OperationAccountChange) {
		t.Fatalf("gpasswd = %#v", exact)
	}
	fallback := Analyze(Input{Argv: []string{"gpasswd", "-M", "a,b", "wheel"}})
	if fallback.Parse.Status != StatusPartial ||
		len(fallback.Commands) != 1 ||
		commandHasOperation(fallback.Commands[0], OperationAccountChange) {
		t.Fatalf("gpasswd fallback = %#v", fallback)
	}
}

func TestActiveHomeIsBoundedTrustedContext(t *testing.T) {
	t.Parallel()
	posix := Analyze(Input{
		Argv:       []string{"cat", "~/.ssh/id_ed25519"},
		ActiveHome: "/Users/fixture",
	})
	if posix.ActiveHome != "/Users/fixture" || len(posix.Paths) != 1 ||
		posix.Paths[0].Resolved != "/Users/fixture/.ssh/id_ed25519" {
		t.Fatalf("posix home = %#v", posix)
	}
	windows := Analyze(Input{
		Argv:        []string{"Get-Content", `~\.ssh\id_ed25519`},
		DialectHint: DialectPowerShell,
		ActiveHome:  `C:\Users\fixture`,
	})
	if windows.ActiveHome != "C:/Users/fixture" ||
		len(windows.Paths) != 1 ||
		windows.Paths[0].Resolved != "C:/Users/fixture/.ssh/id_ed25519" {
		t.Fatalf("windows home = %#v", windows)
	}
	noContext := Analyze(Input{Argv: []string{"cat", "~/.ssh/id_ed25519"}})
	if len(noContext.Paths) != 1 || noContext.Paths[0].Resolved != "" {
		t.Fatalf("implicit home resolution = %#v", noContext)
	}
	untrustedArgs := Analyze(Input{
		Tool: "opaque",
		Args: json.RawMessage(
			`{"active_home":"/attacker/home","path":"~/.ssh/id_ed25519"}`,
		),
	})
	if untrustedArgs.ActiveHome != "" {
		t.Fatalf("args supplied home context: %#v", untrustedArgs)
	}
	for _, invalid := range []string{"relative/home", "/", `C:\`, "$HOME"} {
		facts := Analyze(Input{Argv: []string{"cat", "fixture"}, ActiveHome: invalid})
		if facts.ActiveHome != "" ||
			facts.Parse.Status != StatusInvalid {
			t.Fatalf("invalid home %q = %#v", invalid, facts)
		}
	}
	projected := posix.EnforcementProjection()
	if projected.ActiveHome != posix.ActiveHome {
		t.Fatalf("projection lost home: %#v", projected)
	}
}
