// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// GAP-1732 (the GAP-0475 class): inline interpreter code that builds a path
// to authorized_keys from parts (an f-string over a literal home string,
// concatenation, os.path.join, pathlib) names the protected file in its code
// and is a protected target in action mode, as the literal and expanduser
// forms already are. Code with no such path stays allowed.
func TestActionInterpreterBuiltKeyPathIsProtected(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, code := range []string{
		`h="` + home + `"; open(f"{h}/.ssh/authorized_keys","a").write("# tr-marker\n")`,
		`h="` + home + `"; open(h + "/.ssh/authorized_keys","a").write("x")`,
		`import os; h="` + home + `"; open(os.path.join(h, ".ssh", "authorized_keys"),"a").write("x")`,
		`from pathlib import Path; (Path("` + home + `") / ".ssh" / "authorized_keys2").write_text("x")`,
	} {
		for _, command := range []string{"python3 -c '" + code + "'", "python3 -c '" + code + "' one two"} {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
			}
		}
	}
	for _, command := range []string{
		`perl -e 'my $h = $ENV{HOME}; open(my $f, ">>", "$h/.ssh/authorized_keys")'`,
		`node -e 'require("fs").appendFileSync(require("path").join(process.env.HOME, ".ssh", "authorized_keys"), "x")'`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	for _, command := range []string{
		`python3 -c 'open("notes.txt","a").write("x")'`,
		`python3 -c 'import os; print(os.path.join("a", ".ssh_backup", "keys"))'`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("ActionCommandDecision(%q) = %q, want allow", command, got)
		}
	}
}
