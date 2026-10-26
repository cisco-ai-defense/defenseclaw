// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Copilot CLI on Windows sends a patch through its PowerShell tool as
// apply_patch @'...'@. The envelope word is not a path: its directives are
// (T12b native run on dc-fc-r103-a4-win1, 2026-10-25). The grammar is read the
// same on every OS, so these cases run everywhere.
func TestActionWindowsPatchHereString(t *testing.T) {
	const home, cwd = `C:\Users\dcw4-std2`, `C:\Users\dcw4-std2\copilot-cp2`
	envelope := func(body string) string { return "apply_patch @'\n*** Begin Patch\n" + body + "*** End Patch\n'@" }
	for _, tc := range []struct{ name, command, want string }{
		{"absolute project file", envelope("*** Add File: C:\\Users\\dcw4-std2\\copilot-cp2\\notes-cp2.txt\n+T12b\n"), ""},
		{"nested relative file", envelope("*** Add File: src/app.ts\n+x\n*** Update File: src\\b.ts\n@@\n-a\n+b\n"), ""},
		{"move inside the project", envelope("*** Update File: a.txt\n*** Move to: C:\\Users\\dcw4-std2\\copilot-cp2\\b.txt\n@@\n-a\n+b\n"), ""},
		{"piped here-string", "@'\n*** Begin Patch\n*** Add File: C:\\Users\\dcw4-std2\\copilot-cp2\\notes-cp2.txt\n+T12b\n*** End Patch\n'@ | apply_patch", ""},
		{"piped here-string then a command", "@'\n*** Begin Patch\n*** Add File: src/a.ts\n+x\n*** End Patch\n'@ | apply_patch; Get-Content src/a.ts", ""},
		{"piped protected target", "@'\n*** Begin Patch\n*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+k\n*** End Patch\n'@ | apply_patch", "dynamic-argument"},
		{"piped then a protected write", "@'\n*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch\n'@ | apply_patch; Set-Content C:\\Users\\dcw4-std2\\.ssh\\authorized_keys k", "dynamic-argument"},
		{"protected target", envelope("*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected target by relative escape", envelope("*** Add File: ..\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected target by home form", envelope("*** Add File: ~/.ssh/authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected behind a project file", envelope("*** Add File: notes.txt\n+a\n*** Delete File: C:/Users/dcw4-std2/.ssh/authorized_keys\n"), "dynamic-argument"},
		{"expanding body", "apply_patch @\"\n*** Begin Patch\n*** Add File: notes.txt\n+$k\n*** End Patch\n\"@", "dynamic-argument"},
		{"protected target in a second envelope", envelope("*** Add File: a.txt\n+a\n*** End Patch\n*** Begin Patch\n*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+b\n"), "dynamic-argument"},
		{"protected extra argument", envelope("*** Add File: a.txt\n+a\n") + " C:\\Users\\dcw4-std2\\.ssh\\authorized_keys", "dynamic-argument"},
		{"protected file-fed patch", "apply_patch C:\\Users\\dcw4-std2\\.ssh\\authorized_keys", "dynamic-argument"},
		// A quote inside the here-string body does not end it (loop round 2).
		{"apostrophe in content", envelope("*** Add File: notes.txt\n+It's fine.\n"), ""},
		{"apostrophe in content with CRLF", "apply_patch @'\r\n*** Begin Patch\r\n*** Add File: notes.txt\r\n+It's fine.\r\n*** End Patch\r\n'@", ""},
		{"quotes of both kinds in content", envelope("*** Update File: src\\a.ts\n@@\n-const a = 'x'\n+const a = \"it's\"\n"), ""},
		{"piped apostrophe in content", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+It's fine.\n*** End Patch\n'@ | apply_patch", ""},
		{"piped apostrophe then a command", "@'\n*** Begin Patch\n*** Add File: notes.txt\n+don't\n*** End Patch\n'@ | apply_patch; Get-Content notes.txt", ""},
		{"apostrophe beside a protected target", envelope("*** Add File: notes.txt\n+It's fine.\n*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"piped apostrophe beside a protected target", "@'\n*** Begin Patch\n*** Add File: ~/.ssh/authorized_keys\n+it's mine\n*** End Patch\n'@ | apply_patch", "dynamic-argument"},
		{"apostrophe then a protected write", envelope("*** Add File: a.txt\n+It's\n") + "; Set-Content C:\\Users\\dcw4-std2\\.ssh\\authorized_keys k", "dynamic-argument"},
		{"early closer then a protected write", "apply_patch @'\n*** Begin Patch\n*** Add File: a.txt\n'@; Set-Content ~\\.ssh\\authorized_keys k\n+x\n*** End Patch\n'@", "shell-parse"},
		{"indented closer", "apply_patch @'\n*** Begin Patch\n*** Add File: a.txt\n  '@\n+x\n*** End Patch\n'@", "shell-parse"},
		{"unterminated here-string", "apply_patch @'\n*** Begin Patch\n*** Add File: a.txt\n+It's\n*** End Patch\n", "shell-parse"},
		{"expanding body with an apostrophe", "apply_patch @\"\n*** Begin Patch\n*** Add File: notes.txt\n+It's $k\n*** End Patch\n\"@", "dynamic-argument"},
		// A literal @'...'@ body expands nothing: $ and the backtick are
		// characters there (T12b round c, loop round 1).
		{"literal dollar and backtick in content", envelope("*** Update File: src\\run.ps1\n@@\n-$a = 1\n+$a = \"`t$(Get-Date)\"\n"), ""},
		{"piped literal dollar and backtick in content", "@'\n*** Begin Patch\n*** Add File: C:\\Users\\dcw4-std2\\copilot-cp2\\s.js\n+const s = `it's ${x}`;\n*** End Patch\n'@ | apply_patch", ""},
		{"literal dollar beside a protected target", envelope("*** Add File: a.ps1\n+$x = 1\n*** Add File: ~\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"piped literal dollar beside a protected target", "@'\n*** Begin Patch\n*** Add File: a.ps1\n+$x\n*** Delete File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n*** End Patch\n'@ | apply_patch", "dynamic-argument"},
		{"literal here-string with a trailing word", "apply_patch @'\n*** Begin Patch\n*** Add File: a.txt\n+$x\n*** End Patch\n'@x", "dynamic-argument"},
		{"double-quoted text that looks like a literal here-string", "apply_patch \"@'\n*** Begin Patch\n*** Add File: a.txt\n+$(whoami)\n*** End Patch\n'@\"", "dynamic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision = %q, want %q", got, tc.want)
			}
		})
	}
}

// PowerShell 7 accepts these closing quotes at the start of a line. The
// scanner must expose each following statement instead of treating it as
// literal patch content. Unsupported quote lookalikes stay inside the body.
func TestActionWindowsHereStringTerminatorMatrix(t *testing.T) {
	lineEnds := []struct {
		name, value string
	}{{"LF", "\n"}, {"CRLF", "\r\n"}, {"CR", "\r"}}
	quotes := []struct {
		name, opener       string
		accepted, rejected string
	}{
		{"single", "'", "'‘’‚‛", "“”„‟′＇"},
		{"double", "\"", "\"“”„", "‘’‚‛‟″＂"},
	}
	for _, kind := range quotes {
		for _, opening := range lineEnds {
			for _, closing := range lineEnds {
				for _, group := range []struct {
					quotes string
					want   int
				}{{kind.accepted, 3}, {kind.rejected, 1}} {
					for _, quote := range group.quotes {
						command := "apply_patch @" + kind.opener + opening.value +
							"one" + closing.value + string(quote) +
							"@; Write-Output two; @" + kind.opener +
							opening.value + "three" + closing.value + kind.opener + "@"
						words, _, ok := actionWindowsWords(command)
						statements := 1
						for _, word := range words {
							if word == ";" {
								statements++
							}
						}
						if !ok || statements != group.want {
							t.Errorf("%s opening=%s closing=%s quote=%U: scanner statements=%d ok=%v, PowerShell statements=%d",
								kind.name, opening.name, closing.name, quote, statements, ok, group.want)
						}
					}
				}
			}
		}
	}
}

func TestActionWindowsProtectedHereStringCorpus(t *testing.T) {
	const home, cwd = `C:\Users\Alice`, `C:\Users\Alice\project`
	f, err := os.Open("testdata/action-windows-protected.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var item struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		count++
		t.Run(item.ID, func(t *testing.T) {
			if !strings.Contains(item.Command, "authorized_keys") {
				t.Fatal("corpus row lost its protected target")
			}
			if got := ActionCommandDecision(item.Command, cwd, home); got != "dynamic-argument" {
				t.Fatalf("ActionCommandDecision = %q, want dynamic-argument for the protected write", got)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("protected here-string corpus has %d rows, want 4", count)
	}
}
