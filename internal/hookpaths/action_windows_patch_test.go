// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

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
		{"protected target", envelope("*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected target by relative escape", envelope("*** Add File: ..\\.ssh\\authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected target by home form", envelope("*** Add File: ~/.ssh/authorized_keys\n+k\n"), "dynamic-argument"},
		{"protected behind a project file", envelope("*** Add File: notes.txt\n+a\n*** Delete File: C:/Users/dcw4-std2/.ssh/authorized_keys\n"), "dynamic-argument"},
		{"expanding body", "apply_patch @\"\n*** Begin Patch\n*** Add File: notes.txt\n+$k\n*** End Patch\n\"@", "dynamic-argument"},
		{"protected target in a second envelope", envelope("*** Add File: a.txt\n+a\n*** End Patch\n*** Begin Patch\n*** Add File: C:\\Users\\dcw4-std2\\.ssh\\authorized_keys\n+b\n"), "dynamic-argument"},
		{"protected extra argument", envelope("*** Add File: a.txt\n+a\n") + " C:\\Users\\dcw4-std2\\.ssh\\authorized_keys", "dynamic-argument"},
		{"protected file-fed patch", "apply_patch C:\\Users\\dcw4-std2\\.ssh\\authorized_keys", "dynamic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision = %q, want %q", got, tc.want)
			}
		})
	}
}
