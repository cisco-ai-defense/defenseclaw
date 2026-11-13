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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func encodedPowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func hookShellArgs(t *testing.T, command string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A static launcher, call block or Invoke-Expression literal is the script it
// runs: the same command, paths and status as the bare script, with the
// launcher kept only as HostWrappers evidence.
func TestHostWrappersAreTransparentToFacts(t *testing.T) {
	const bare = `Get-Content C:\tmp\a.txt`
	bareFacts := Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, bare)})
	if !bareFacts.Authoritative() || len(bareFacts.Commands) != 1 {
		t.Fatalf("bare script facts = %#v", bareFacts)
	}
	for _, test := range []struct {
		name, tool, command string
	}{
		{"powershell without profile switch", "PowerShell", `powershell -Command "Get-Content C:\tmp\a.txt"`},
		{"powershell abbreviations", "PowerShell", `powershell.exe -nop -noni -ex Bypass -c "Get-Content C:\tmp\a.txt"`},
		{"pwsh single quoted", "PowerShell", `pwsh -c 'Get-Content C:\tmp\a.txt'`},
		{"pwsh joins words", "PowerShell", `pwsh -Command Get-Content C:\tmp\a.txt`},
		{"encoded command", "PowerShell", `powershell -EncodedCommand ` + encodedPowerShell(bare)},
		{"call block", "PowerShell", `& { Get-Content C:\tmp\a.txt }`},
		{"invoke expression literal", "PowerShell", `Invoke-Expression 'Get-Content C:\tmp\a.txt'`},
		{"nested launchers", "PowerShell", `powershell -c 'pwsh -c ''Get-Content C:\tmp\a.txt'''`},
		{"cmd launcher", "PowerShell", `cmd /c type C:\tmp\a.txt`},
		{"Git Bash running powershell.exe", "Bash", `powershell.exe -NoProfile -Command 'Get-Content C:/tmp/a.txt'`},
		{"Git Bash running pwsh without profile switch", "Bash", `pwsh -c 'Get-Content C:/tmp/a.txt'`},
		{"statement list", "PowerShell", `Set-Location C:\tmp; powershell -c "Get-Content C:\tmp\a.txt"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: hookShellArgs(t, test.command), ActiveHome: `C:\Users\alice`})
			want := "get-content"
			if strings.HasPrefix(test.command, "cmd") {
				want = "type"
			}
			if len(facts.HostWrappers) == 0 || !hasExecutable(facts.Commands, want) {
				t.Fatalf("wrapped facts = %#v", facts)
			}
			for _, command := range facts.Commands {
				if len(command.Wrappers) != 0 || command.ParentCommandID != 0 {
					t.Fatalf("a launcher was recorded as an execution wrapper: %#v", command)
				}
				if command.Program == "powershell" || command.Program == "pwsh" || command.Program == "cmd" {
					t.Fatalf("the launcher is a command of the call: %#v", facts.Commands)
				}
			}
			if !strings.Contains(test.name, "statement list") &&
				(!facts.Authoritative() || facts.Parse.Dialect == DialectMixed) {
				t.Fatalf("wrapped parse = %#v", facts.Parse)
			}
		})
	}
}

// Anything psparse cannot resolve to one static script is not unwrapped: the
// launcher stays an ordinary command with unknown operands.
func TestHostWrappersStayOpaqueWhenTheScriptIsNotStatic(t *testing.T) {
	for _, test := range []struct {
		name, command string
	}{
		{"variable payload", `powershell -Command $payload`},
		{"sub-expression payload", `powershell -Command "$(Get-Secret)"`},
		{"file", `powershell -File C:\tmp\run.ps1`},
		{"stdin", `powershell -Command -`},
		{"stop parsing tail", `powershell -Command --% Get-Content C:\tmp\a.txt`},
		{"working directory", `powershell -WorkingDirectory C:\other -Command "Get-Content a.txt"`},
		{"working directory abbreviation", `pwsh -wo C:\other -c "Get-Content a.txt"`},
		{"empty argument", `pwsh -Command Get-Content ''`},
		{"unknown host switch", `powershell -Frobnicate -Command "Get-Content C:\tmp\a.txt"`},
		{"start process child", `Start-Process powershell -ArgumentList '-c','Get-Content C:\tmp\a.txt'`},
		{"arbitrary path launcher", `C:\tmp\powershell.exe -Command "Get-Content C:\tmp\a.txt"`},
		{"encoded command that is not base64", `powershell -EncodedCommand not-base64!`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, test.command)})
			if facts.Authoritative() || len(facts.HostWrappers) != 0 {
				t.Fatalf("an opaque launcher was unwrapped: %#v", facts)
			}
			if hasExecutable(facts.Commands, "get-content") {
				t.Fatalf("the unresolved script was projected: %#v", facts.Commands)
			}
		})
	}
}

func TestHostWrappersKeepOpenHostPartial(t *testing.T) {
	for _, test := range []struct {
		name, tool, command string
		dialect             Dialect
	}{
		{"cmd /k", "shell", `cmd /k "type C:\tmp\a.txt"`, DialectCMD},
		{"powershell -NoExit", "PowerShell", `powershell -NoExit -c "Get-Content C:\tmp\a.txt"`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Command: test.command, DialectHint: test.dialect})
			if facts.Authoritative() || len(facts.HostWrappers) == 0 ||
				(!hasExecutable(facts.Commands, "type") && !hasExecutable(facts.Commands, "get-content")) {
				t.Fatalf("keep-open launcher facts = %#v", facts)
			}
		})
	}
}

func TestHostWrappersStopAtTheWrapperDepth(t *testing.T) {
	source := `Get-Content C:\tmp\a.txt`
	for layer := 0; layer < maxWrapperDepth+1; layer++ {
		source = `powershell -c '` + strings.ReplaceAll(source, `'`, `''`) + `'`
	}
	facts := Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, source)})
	if facts.Authoritative() || facts.Parse.Status != StatusLimitExceeded ||
		!containsIssue(facts.Parse.Issues, IssueWrapperLimit) {
		t.Fatalf("over-deep launchers = %#v", facts.Parse)
	}
	within := `Get-Content C:\tmp\a.txt`
	for layer := 0; layer < maxWrapperDepth-1; layer++ {
		within = `powershell -c '` + strings.ReplaceAll(within, `'`, `''`) + `'`
	}
	facts = Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, within)})
	if !facts.Authoritative() || len(facts.HostWrappers) != maxWrapperDepth-1 || !hasExecutable(facts.Commands, "get-content") {
		t.Fatalf("launchers within the depth = %#v", facts)
	}
}

// Launcher words are evidence only: the wrapped and the bare spelling of the
// same script have the same commands, paths and operations.
func TestHostWrappersGiveTheSameCommandsPathsAndOperations(t *testing.T) {
	const script = `Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value x`
	bare := Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, script), ActiveHome: `C:\Users\alice`})
	for _, wrapped := range []string{
		`powershell -Command "` + script + `"`,
		`powershell -NoProfile -EncodedCommand ` + encodedPowerShell(script),
		`& { ` + script + ` }`,
		`Invoke-Expression '` + script + `'`,
	} {
		facts := Analyze(Input{Tool: "PowerShell", Args: hookShellArgs(t, wrapped), ActiveHome: `C:\Users\alice`})
		if len(facts.Commands) != len(bare.Commands) || len(facts.Paths) != len(bare.Paths) ||
			facts.Parse.Status != bare.Parse.Status || facts.Parse.Dialect != bare.Parse.Dialect {
			t.Fatalf("wrapped %q facts differ from the bare script:\nwrapped=%#v\nbare=%#v", wrapped, facts, bare)
		}
		for index, command := range facts.Commands {
			other := bare.Commands[index]
			if command.Program != other.Program || !equalStrings(command.Argv, other.Argv) ||
				len(command.Operations) != len(other.Operations) {
				t.Fatalf("wrapped %q command differs: %#v vs %#v", wrapped, command, other)
			}
		}
		for index, path := range facts.Paths {
			if path.Value != bare.Paths[index].Value || path.Access != bare.Paths[index].Access {
				t.Fatalf("wrapped %q path differs: %#v vs %#v", wrapped, path, bare.Paths[index])
			}
		}
	}
}
