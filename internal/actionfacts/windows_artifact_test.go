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
	"reflect"
	"testing"
)

func TestAnalyzeWindowsStaticScriptArtifacts(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		dialect    Dialect
		command    string
		argv       []string
		program    string
		access     PathAccess
		normalized string
	}{
		{
			name: "PowerShell dot source", tool: "powershell",
			dialect: DialectPowerShell,
			command: `. 'C:\work\task.ps1'`, program: ".",
			access: PathAccessRead, normalized: "C:/work/task.ps1",
		},
		{
			name: "PowerShell direct script", tool: "powershell",
			dialect: DialectPowerShell,
			command: `C:\work\task.ps1`, program: "task.ps1",
			access: PathAccessExecute, normalized: "C:/work/task.ps1",
		},
		{
			name: "PowerShell call operator module", tool: "powershell",
			dialect: DialectPowerShell,
			command: `& 'C:\work\module.psm1'`, program: "module.psm1",
			access: PathAccessExecute, normalized: "C:/work/module.psm1",
		},
		{
			name: "PowerShell profile-disabled file", tool: "powershell",
			dialect: DialectPowerShell,
			command: `powershell -NoProfile -File 'C:\work\task.ps1'`,
			program: "powershell", access: PathAccessExecute,
			normalized: "C:/work/task.ps1",
		},
		{
			name: "CMD quoted direct command script", tool: "cmd",
			dialect: DialectCMD,
			command: `"C:\work\task.cmd"`, program: "task.cmd",
			access: PathAccessExecute, normalized: "C:/work/task.cmd",
		},
		{
			name: "CMD direct batch script", tool: "cmd",
			dialect: DialectCMD,
			command: `C:\work\task.bat`, program: "task.bat",
			access: PathAccessExecute, normalized: "C:/work/task.bat",
		},
		{
			name: "structured PowerShell dot source", tool: "powershell",
			dialect: DialectPowerShell,
			argv:    []string{".", `C:\work\task.ps1`}, program: ".",
			access: PathAccessRead, normalized: "C:/work/task.ps1",
		},
		{
			name: "structured PowerShell profile-disabled file", tool: "powershell",
			dialect: DialectPowerShell,
			argv: []string{
				"powershell", "-NoProfile", "-File", `C:\work\task.ps1`,
			},
			program: "powershell", access: PathAccessExecute,
			normalized: "C:/work/task.ps1",
		},
		{
			name: "structured CMD direct command script", tool: "cmd",
			dialect: DialectCMD,
			argv:    []string{`C:\work\task.cmd`}, program: "task.cmd",
			access: PathAccessExecute, normalized: "C:/work/task.cmd",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        test.tool,
				Command:     test.command,
				Argv:        test.argv,
				CWD:         `C:\work`,
				DialectHint: test.dialect,
			})
			if facts.Parse.Status != StatusPartial ||
				!reflect.DeepEqual(facts.Parse.Issues, []IssueCode{IssueOpaqueArtifact}) {
				t.Fatalf("parse = %#v", facts.Parse)
			}
			if len(facts.Commands) != 1 || len(facts.Paths) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			command := facts.Commands[0]
			if command.Program != test.program || command.Effect != EffectExecute ||
				!command.ArgvComplete || command.ParentCommandID != 0 ||
				command.PipelineID != 0 || len(command.Redirects) != 0 ||
				len(command.Wrappers) != 0 ||
				!commandHasOperation(command, OperationExecute) {
				t.Fatalf("command = %#v", command)
			}
			path := facts.Paths[0]
			if path.CommandID != command.ID || path.Access != test.access ||
				path.Normalized != test.normalized || !path.Absolute ||
				path.Resolved != test.normalized {
				t.Fatalf("path = %#v", path)
			}
			if facts.EnforcementEligible() ||
				facts.EnforcementProjection().EnforcementEligible() {
				t.Fatal("opaque script became ordinary enforcement input")
			}
		})
	}
}

func TestAnalyzeWindowsScriptArtifactsKeepAdditionalUncertainty(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		dialect    Dialect
		command    string
		argv       []string
		wantOpaque bool
	}{
		{
			name: "PowerShell outer control flow", tool: "powershell",
			dialect: DialectPowerShell,
			command: `C:\work\task.ps1; Write-Output done`, wantOpaque: true,
		},
		{
			name: "PowerShell dynamic call target", tool: "powershell",
			dialect: DialectPowerShell,
			command: `& $script`, wantOpaque: false,
		},
		{
			name: "PowerShell profile-enabled file", tool: "powershell",
			dialect: DialectPowerShell,
			command: `powershell -File 'C:\work\task.ps1'`, wantOpaque: true,
		},
		{
			name: "PowerShell relative file launcher", tool: "powershell",
			dialect: DialectPowerShell,
			command: `powershell -NoProfile -File '.\task.ps1'`, wantOpaque: false,
		},
		{
			name: "PowerShell script arguments", tool: "powershell",
			dialect: DialectPowerShell,
			command: `& 'C:\work\task.ps1' safe`, wantOpaque: true,
		},
		{
			name: "CMD outer control flow", tool: "cmd", dialect: DialectCMD,
			command: `C:\work\task.cmd & echo done`, wantOpaque: true,
		},
		{
			name: "CMD dynamic target", tool: "cmd", dialect: DialectCMD,
			command: `%SCRIPT%`, wantOpaque: false,
		},
		{
			name: "structured PowerShell profile-enabled file", tool: "powershell",
			dialect:    DialectPowerShell,
			argv:       []string{"powershell", "-File", `C:\work\task.ps1`},
			wantOpaque: false,
		},
		{
			name: "structured CMD script arguments", tool: "cmd",
			dialect: DialectCMD,
			argv:    []string{`C:\work\task.cmd`, "safe"}, wantOpaque: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        test.tool,
				Command:     test.command,
				Argv:        test.argv,
				CWD:         `C:\work`,
				DialectHint: test.dialect,
			})
			if facts.Parse.Status == StatusComplete || facts.Authoritative() ||
				facts.EnforcementEligible() ||
				(len(facts.Parse.Issues) == 1 &&
					facts.Parse.Issues[0] == IssueOpaqueArtifact) {
				t.Fatalf("uncertain script form gained authority: %#v", facts)
			}
			if got := containsIssue(facts.Parse.Issues, IssueOpaqueArtifact); got != test.wantOpaque {
				t.Fatalf("opaque issue=%t want %t: %#v", got, test.wantOpaque, facts.Parse)
			}
		})
	}
}
