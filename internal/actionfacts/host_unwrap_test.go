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
	"reflect"
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

func hookShellInput(t *testing.T, tool, command string) Input {
	t.Helper()
	return Input{Tool: tool, Args: hookShellArgs(t, command), ActiveHome: `C:\Users\alice`}
}

// A static launcher, call block or Invoke-Expression literal has a script
// reading: the same commands, paths and status as the bare script.
func TestHostScriptTwinIsTheScriptTheCallRuns(t *testing.T) {
	const bare = `Get-Content C:\tmp\a.txt`
	bareFacts := Analyze(hookShellInput(t, "PowerShell", bare))
	if !bareFacts.Authoritative() || len(bareFacts.Commands) != 1 {
		t.Fatalf("bare script facts = %#v", bareFacts)
	}
	for _, test := range []struct {
		name, tool, command string
	}{
		{"powershell without profile switch", "PowerShell", `powershell -Command "Get-Content C:\tmp\a.txt"`},
		{"powershell abbreviations", "PowerShell", `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -c "Get-Content C:\tmp\a.txt"`},
		{"pwsh single quoted", "PowerShell", `pwsh -c 'Get-Content C:\tmp\a.txt'`},
		{"pwsh joins words", "PowerShell", `pwsh -Command Get-Content C:\tmp\a.txt`},
		{"encoded command", "PowerShell", `powershell -EncodedCommand ` + encodedPowerShell(bare)},
		{"call block", "PowerShell", `& { Get-Content C:\tmp\a.txt }`},
		{"invoke expression literal", "PowerShell", `Invoke-Expression 'Get-Content C:\tmp\a.txt'`},
		{"nested launchers", "PowerShell", `powershell -c 'pwsh -c ''Get-Content C:\tmp\a.txt'''`},
		{"Git Bash running powershell.exe", "Bash", `powershell.exe -NoProfile -Command 'Get-Content C:/tmp/a.txt'`},
		{"Git Bash running pwsh without profile switch", "Bash", `pwsh -c 'Get-Content C:/tmp/a.txt'`},
		{"statement list", "PowerShell", `Set-Location C:\tmp; powershell -c "Get-Content C:\tmp\a.txt"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := hookShellInput(t, test.tool, test.command)
			twin, ok := HostScriptTwin(input, Analyze(input))
			if !ok {
				t.Fatal("no script reading")
			}
			if len(twin.Args) != 0 || len(twin.Argv) != 0 || twin.Command == "" {
				t.Fatalf("twin input = %#v", twin)
			}
			facts := Analyze(twin)
			if !hasExecutable(facts.Commands, "get-content") {
				t.Fatalf("script reading facts = %#v", facts)
			}
			for _, command := range facts.Commands {
				if command.Program == "powershell" || command.Program == "pwsh" {
					t.Fatalf("the launcher is a command of its own script reading: %#v", facts.Commands)
				}
			}
			if !strings.Contains(test.name, "statement list") && !facts.Authoritative() {
				t.Fatalf("script reading parse = %#v", facts.Parse)
			}
		})
	}
	for _, command := range []string{
		`cmd /c type C:\tmp\a.txt`,
		`cmd.exe /d /c type C:\tmp\a.txt`,
	} {
		input := hookShellInput(t, "PowerShell", command)
		twin, ok := HostScriptTwin(input, Analyze(input))
		if !ok || !hasExecutable(Analyze(twin).Commands, "type") || twin.DialectHint != DialectCMD {
			t.Fatalf("cmd launcher %q: twin=%#v ok=%v", command, twin, ok)
		}
	}
}

// A structured argv launcher has the same reading.
func TestHostScriptTwinReadsAStructuredLauncher(t *testing.T) {
	input := Input{Tool: "exec", Argv: []string{"pwsh", "-c", `Get-Content C:\tmp\a.txt`}}
	twin, ok := HostScriptTwin(input, Analyze(input))
	if !ok || !hasExecutable(Analyze(twin).Commands, "get-content") {
		t.Fatalf("structured launcher: twin=%#v ok=%v", twin, ok)
	}
}

// Anything psparse cannot resolve to one static script has no reading: the
// call stays exactly as unknown as the tokenizer left it.
func TestHostScriptTwinIsAbsentWhenTheScriptIsNotStatic(t *testing.T) {
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
		{"working directory alias", `pwsh -wd C:\other -c "Get-Content a.txt"`},
		{"empty argument", `pwsh -Command Get-Content ''`},
		{"colon-glued switch", `pwsh -Command: "Get-Content C:\tmp\a.txt"`},
		{"number word", `pwsh -Command Get-Content 0x10`},
		{"unknown host switch", `powershell -Frobnicate -Command "Get-Content C:\tmp\a.txt"`},
		{"start process child", `Start-Process powershell -ArgumentList '-c','Get-Content C:\tmp\a.txt'`},
		{"arbitrary path launcher", `C:\tmp\powershell.exe -Command "Get-Content C:\tmp\a.txt"`},
		{"encoded command that is not base64", `powershell -EncodedCommand not-base64!`},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := hookShellInput(t, "PowerShell", test.command)
			if twin, ok := HostScriptTwin(input, Analyze(input)); ok {
				t.Fatalf("an opaque launcher has a reading: %#v", twin)
			}
		})
	}
}

func TestHostScriptTwinStopsAtTheWrapperDepth(t *testing.T) {
	source := `Get-Content C:\tmp\a.txt`
	for layer := 0; layer < maxWrapperDepth+1; layer++ {
		source = `powershell -c '` + strings.ReplaceAll(source, `'`, `''`) + `'`
	}
	input := hookShellInput(t, "PowerShell", source)
	if twin, ok := HostScriptTwin(input, Analyze(input)); ok {
		t.Fatalf("over-deep launchers have a reading: %#v", twin)
	}
	within := `Get-Content C:\tmp\a.txt`
	for layer := 0; layer < maxWrapperDepth-1; layer++ {
		within = `powershell -c '` + strings.ReplaceAll(within, `'`, `''`) + `'`
	}
	input = hookShellInput(t, "PowerShell", within)
	twin, ok := HostScriptTwin(input, Analyze(input))
	if !ok || !hasExecutable(Analyze(twin).Commands, "get-content") {
		t.Fatalf("launchers within the depth: twin=%#v ok=%v", twin, ok)
	}
}

// ADDITIVE ONLY (S7 lead constraint). psparse is not yet reliable in every
// modelled shape, so it may only add readings: the facts of a call as written
// never depend on it. For every call below, Analyze gives the same facts whether
// or not a script reading exists; the launcher stays the command the tokenizer
// saw with the status and issues it gave; a reading never mutates its input; and
// a call psparse cannot resolve is neither completed nor made clean.
func TestHostScriptTwinNeverChangesTheFactsOfTheCallAsWritten(t *testing.T) {
	calls := []Input{
		hookShellInput(t, "PowerShell", `powershell -Command "Get-Content C:\tmp\a.txt"`),
		hookShellInput(t, "PowerShell", `powershell -NoProfile -Command "Remove-Item C:\victim"`),
		hookShellInput(t, "PowerShell", `pwsh -c 'Get-Content C:\tmp\a.txt'`),
		hookShellInput(t, "PowerShell", `& { Remove-Item C:\victim }`),
		hookShellInput(t, "PowerShell", `Invoke-Expression 'Remove-Item C:\victim'`),
		hookShellInput(t, "PowerShell", `cmd /c del C:\victim`),
		hookShellInput(t, "PowerShell", `powershell -Command $payload`),
		hookShellInput(t, "PowerShell", `powershell -File C:\tmp\run.ps1`),
		hookShellInput(t, "PowerShell", `powershell -Command --% Remove-Item C:\victim`),
		hookShellInput(t, "Bash", `powershell.exe -c "Remove-Item C:\victim"`),
		hookShellInput(t, "Bash", `cmd.exe /d /c "del C:\victim"`),
		hookShellInput(t, "Bash", `rm -rf /tmp/victim`),
		{Tool: "exec", Argv: []string{"pwsh", "-c", `Remove-Item C:\victim`}},
		{Tool: "exec", Argv: []string{"cmd.exe", "/c", `del C:\victim`}},
	}
	for _, input := range calls {
		before := Analyze(input)
		snapshot := Input{Tool: input.Tool, Args: append(json.RawMessage(nil), input.Args...), Argv: append([]string(nil), input.Argv...), ActiveHome: input.ActiveHome}
		twin, ok := HostScriptTwin(input, before)
		after := Analyze(input)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("a script reading changed the facts of the call as written:\nbefore=%#v\nafter=%#v", before, after)
		}
		if !reflect.DeepEqual(snapshot.Args, append(json.RawMessage(nil), input.Args...)) ||
			!reflect.DeepEqual(snapshot.Argv, append([]string(nil), input.Argv...)) {
			t.Fatalf("a script reading mutated its input: %#v", input)
		}
		if !ok {
			continue
		}
		// The launcher or call block is still part of the call as written,
		// and an unproven call stays unproven: a reading is a second set of
		// facts, never the answer for the first.
		if before.Authoritative() != Analyze(input).Authoritative() {
			t.Fatalf("authority of the call as written changed: %#v", before.Parse)
		}
		if len(twin.Args) != 0 || len(twin.Argv) != 0 {
			t.Fatalf("a reading keeps the launcher payload: %#v", twin)
		}
	}
	// Calls psparse cannot resolve have no reading and stay unproven as written.
	for _, command := range []string{
		`powershell -Command $payload`,
		`powershell -File C:\tmp\run.ps1`,
		`powershell -Command --% Remove-Item C:\victim`,
	} {
		input := hookShellInput(t, "PowerShell", command)
		facts := Analyze(input)
		if _, ok := HostScriptTwin(input, facts); ok || facts.Authoritative() {
			t.Fatalf("an unresolved launcher %q was read or completed: %#v", command, facts.Parse)
		}
	}
}

// Statements after a top-level exit never run, so the script reading drops them.
func TestHostScriptTwinDropsStatementsAfterExit(t *testing.T) {
	for _, test := range []struct {
		name, command string
		keeps, drops  string
	}{
		{"exit first", `pwsh -c "exit; Get-Content C:\tmp\a.txt"`, "exit", "Get-Content"},
		{"exit after a statement", `pwsh -c "Get-Date; exit; Remove-Item C:\tmp\a.txt"`, "Get-Date", "Remove-Item"},
		{"conditional exit keeps the rest", `pwsh -c 'if ($x) { exit }; Get-Content C:\tmp\a.txt'`, "Get-Content", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := hookShellInput(t, "PowerShell", test.command)
			twin, ok := HostScriptTwin(input, Analyze(input))
			if !ok {
				t.Fatal("no script reading")
			}
			if !strings.Contains(twin.Command, test.keeps) ||
				test.drops != "" && strings.Contains(twin.Command, test.drops) {
				t.Fatalf("script reading = %q", twin.Command)
			}
		})
	}
}
