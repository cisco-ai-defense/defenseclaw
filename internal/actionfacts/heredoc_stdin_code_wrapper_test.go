// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// A heredoc, stdin redirect or pipeline that feeds a command which runs its
// standard input as code behind a wrapper or a scheduler keeps the parse
// partial, quoted or not, as a direct shell does; a body with the legacy
// $[expr] arithmetic is not parameter-only. The benign twins stay complete
// (rel-1-0-6:GAP-0419).
func TestPOSIXStdinCodeBehindAWrapperStaysPartial(t *testing.T) {
	partial := []string{
		"sudo sh",
		"sudo bash",
		"sudo -s",
		"sudo -u root sh",
		"sudo -E -u root bash -l",
		"doas sh",
		"pkexec bash",
		"su",
		"su -",
		"su - root",
		"at now",
		"at now + 1 minute",
		"batch",
		"crontab -",
		"crontab",
	}
	for _, wrapper := range partial {
		for _, form := range []string{
			wrapper + " <<X\nrm -rf $D\nX",
			wrapper + " <<\x27X\x27\nrm -rf /tmp/d\nX",
			"cat <<X | " + wrapper + "\nrm -rf $D\nX",
			wrapper + " < /tmp/job.sh",
		} {
			t.Run(form, func(t *testing.T) {
				facts := Analyze(Input{Tool: "shell", Command: form, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
				if facts.Authoritative() {
					t.Fatalf("stdin run as code became authoritative: %#v", facts.Parse)
				}
			})
		}
	}
	for _, form := range []string{
		"cat > /tmp/rv <<X\n$[n]\nX",
		"cat > /tmp/rv <<X\nvalue $[1+1]\nX",
	} {
		t.Run(form, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: form, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
			if facts.Authoritative() {
				t.Fatalf("a $[expr] body became authoritative: %#v", facts.Parse)
			}
		})
	}
	for _, form := range []string{
		"cat > /etc/sudoers <<X\nDefaults env_reset\nX",
		"cat <<X | sudo tee /repo/out.txt\nhello $USER\nX",
		"sudo tee /repo/out.txt <<X\nhello $USER\nX",
		"sudo sh -c \x27echo ok\x27 <<X\n$USER\nX",
		"su -c \x27echo ok\x27 <<X\n$USER\nX",
		"crontab /repo/jobs.cron",
		"git commit -F - <<X\nfix: $MSG\nX",
		"cat > /repo/notes.md <<X\nprice [1] $[ in text\nX",
	} {
		want := form != "cat > /repo/notes.md <<X\nprice [1] $[ in text\nX"
		t.Run(form, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: form, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
			if facts.Authoritative() != want {
				t.Fatalf("complete = %t, want %t: %#v", facts.Authoritative(), want, facts.Parse)
			}
		})
	}
}
