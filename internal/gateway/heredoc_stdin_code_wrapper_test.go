// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows are POSIX shell calls and use the POSIX managed peer fixture.

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestHeredocStdinCodeAndBenignHeredocsInFourCells: a heredoc run as code
// behind a wrapper or a scheduler is never judged as a complete, harmless
// call, a body with the legacy $[expr] arithmetic is not read as
// parameter-only, the main sudoers file heredoc keeps its decision, and no
// benign heredoc is blocked, in the default and strict packs, per-user and
// managed (rel-1-0-6:GAP-0419).
func TestHeredocStdinCodeAndBenignHeredocsInFourCells(t *testing.T) {
	type row struct {
		command string
		want    func(profile string) string // block, alert or allow; "" = not block
	}
	notBlocked := func(string) string { return "" }
	allow := func(string) string { return "allow" }
	rows := []row{
		{"sudo sh <<X\necho Defaults use_pty >> /etc/sudoers\nX", notBlocked},
		{"sudo bash <<X\nrm -rf $D\nX", notBlocked},
		{"sudo -s <<X\nrm -rf $D\nX", notBlocked},
		{"sudo -u root sh <<X\nrm -rf $D\nX", notBlocked},
		{"su <<X\nrm -rf $D\nX", notBlocked},
		{"su - <<X\nrm -rf $D\nX", notBlocked},
		{"at now <<X\nrm -rf $D\nX", notBlocked},
		{"crontab - <<X\n* * * * * $CMD\nX", notBlocked},
		{"cat <<X | sudo sh\nrm -rf $D\nX", notBlocked},
		{"cat > /tmp/rv-gap0400 <<X\n$[n]\nX", allow},
		// The main file keeps its decision: HIGH alerts in default, strict blocks.
		{"cat > /etc/sudoers <<X\nDefaults env_reset\nX", func(profile string) string {
			if profile == "strict" {
				return "block"
			}
			return "alert"
		}},
		// Benign heredocs stay allowed.
		{"git commit -F - <<X\nfix: $MSG\nX", allow},
		{"cat > notes.md <<X\n# $TITLE\nX", allow},
		{"cat > notes.md <<X\nprice $[ x\nX", allow},
		{"sudo tee out.txt <<X\nhello $USER\nX", allow},
		{"kubectl apply -f - <<X\nkind: Pod\nname: $N\nX", allow},
		{"psql -d app <<X\nselect 1;\nX", allow},
		{"grep -c -f - /etc/sudoers <<X\n$USER\nX", allow},
		{"sudo sh -c \x27echo ok\x27 <<X\n$USER\nX", notBlocked},
		{"crontab -l", notBlocked},
	}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, r := range rows {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + strings.SplitN(r.command, "\n", 2)[0]
				t.Run(name, func(t *testing.T) {
					hook := sudoersHookRow{"claudecode", "heredoc", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": r.command}))}
					blocked, _, body := postSudoersHook(t, hook, profile, managed)
					got := "allow"
					if blocked {
						got = "block"
					} else if strings.Contains(body, `"action":"alert"`) {
						got = "alert"
					}
					want := r.want(profile)
					if want == "" {
						if got == "block" {
							t.Fatalf("blocked: %.600s", body)
						}
						return
					}
					if got != want {
						t.Fatalf("decision %s, want %s: %.600s", got, want, body)
					}
				})
			}
		}
	}
}
