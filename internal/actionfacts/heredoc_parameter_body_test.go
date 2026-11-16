// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// An unquoted heredoc whose body expands only parameters runs nothing: the
// parse stays complete, the redirect target is a proven write and the stdin
// text is unknown. A body with a command, arithmetic or process
// substitution, an interpreter fed the body, and a : comment block stay
// partial (rel-1-0-6:GAP-0399).
func TestPOSIXParameterOnlyHeredocKeepsTheRedirectTarget(t *testing.T) {
	for _, row := range []struct {
		command, write string
		complete       bool
	}{
		{"cat > /etc/sudoers <<X\nDefaults env_reset\nX", "/etc/sudoers", true},
		{"cat >> /home/alice/.zshrc <<EOF\nexport A=$B ${C:-d}\nEOF", "/home/alice/.zshrc", true},
		{"cat <<EOF | tee /etc/sudoers\nDefaults $X\nEOF", "/etc/sudoers", true},
		{"cat > /etc/sudoers <<X\nDefaults $(id -un)\nX", "", false},
		{"cat > /etc/sudoers <<X\nDefaults `id -un`\nX", "", false},
		{"cat > /etc/sudoers <<X\nDefaults $((1+1))\nX", "", false},
		{"cat > /etc/sudoers <<X\nDefaults ${A:-$(id)}\nX", "", false},
		{"bash <<EOF\nrm -rf $DIR\nEOF", "", false},
		{": <<EOF\nrm -rf /\nEOF", "", false},
	} {
		t.Run(row.command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: row.command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
			if facts.Authoritative() != row.complete {
				t.Fatalf("complete = %t, want %t: %#v", facts.Authoritative(), row.complete, facts.Parse)
			}
			if !row.complete {
				return
			}
			for _, path := range facts.Paths {
				if path.Resolved == row.write && (path.Access == PathAccessWrite || path.Access == PathAccessAppend) {
					for _, command := range facts.Commands {
						if command.LiteralStdinComplete {
							t.Fatalf("an expanding body became literal stdin: %#v", command)
						}
					}
					return
				}
			}
			t.Fatalf("no write of %s in %#v", row.write, facts.Paths)
		})
	}
}
