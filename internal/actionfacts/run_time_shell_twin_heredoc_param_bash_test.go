// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRunTimeShellTwinHeredocMatchesBash: for each body piped to bash from an
// unquoted and a quoted here-document, the twin, when it reads the text, runs
// to the same output as bash runs the original; a twin that cannot read the
// unquoted text the same way reports it unread (rel-1-0-10:GAP-1148,
// GAP-1193). The bodies only print. Rows from the g1137 round-2 review
// differential (s7-g1137rev2).
func TestRunTimeShellTwinHeredocMatchesBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	run := func(command string) string {
		cmd := exec.Command("bash", "-c", command)
		cmd.Env = append(os.Environ(), "HOME=/hh")
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "ERR:" + err.Error() + ":" + string(out)
		}
		return string(out)
	}
	bodies := []string{
		"printf '<%s>' \\$HOME/x",
		"printf '<%s>' \\\\$HOME/x",
		"printf '<%s>' '$HOME'/x",
		"printf '<%s>' \"$HOME\"/x",
		"printf '<%s>' \\\n$HOME/x",
		"printf '<%s>' \\~/x \\a",
		"printf '<%s>' \\`echo zz\\`/x",
		"printf '<%s>' \"a\\\"b\" \\\\\\$HOME",
		"X='a b'; printf '<%s>' $X",
		"printf '<%s>' \\\\\\\\$HOME",
		"printf '<%s>' 'a\\\\b'",
		"# $HOME\nprintf '<%s>' ${HOME}",
	}
	for _, body := range bodies {
		for _, delim := range []string{"EOF", "'EOF'"} {
			command := "cat <<" + delim + " | bash\n" + body + "\nEOF"
			real := run(command)
			twin, ok, _, unread := RunTimeShellTwin(command)
			switch {
			case ok && run(twin) != real:
				t.Errorf("twin of %q runs to %q, bash runs %q", command, run(twin), real)
			case !ok && !unread:
				t.Errorf("RunTimeShellTwin(%q): no twin and not unread", command)
			case !ok && delim == "'EOF'":
				t.Errorf("RunTimeShellTwin(%q): a quoted body is not read", command)
			}
		}
	}
}
