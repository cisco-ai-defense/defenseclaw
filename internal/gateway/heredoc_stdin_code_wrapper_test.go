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

// TestStdinCodeWrapperKeepsTheStrictSignal: the stdin-code mark keeps the
// action partial, but the sudo and crontab argv still prove the elevated
// shell and the crontab install, so strict keeps its CMD-SUDO alert and its
// detection-only CMD-CRONTAB finding, as for the complete action. The
// default and permissive packs disable both rules (expression: false) and
// still name neither (rel-1-0-6:GAP-0419 review round 3).
func TestStdinCodeWrapperKeepsTheStrictSignal(t *testing.T) {
	rows := []struct{ command, rule, strict string }{
		{"sudo sh <<X\nid\nX", "CMD-SUDO", "alert"},
		{"sudo -s <<\x27X\x27\nid\nX", "CMD-SUDO", "alert"},
		{"sudo sh < /tmp/job.sh", "CMD-SUDO", "alert"},
		{"sudo sh </dev/null", "CMD-SUDO", "alert"},
		{"cat <<X | sudo sh\nid\nX", "CMD-SUDO", "alert"},
		{"sudo --user root sh <<X\nid\nX", "CMD-SUDO", "alert"},
		{"crontab - <<X\n* * * * * $CMD\nX", "CMD-CRONTAB", "allow"},
		{"crontab - <<\x27X\x27\n* * * * * /bin/true\nX", "CMD-CRONTAB", "allow"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + strings.SplitN(row.command, "\n", 2)[0]
				t.Run(name, func(t *testing.T) {
					hook := sudoersHookRow{"claudecode", "wrapper", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": row.command}))}
					blocked, _, body := postSudoersHook(t, hook, profile, managed)
					got := "allow"
					if blocked {
						got = "block"
					} else if strings.Contains(body, `"action":"alert"`) {
						got = "alert"
					}
					named := strings.Contains(body, row.rule+":")
					if profile != "strict" {
						if named || got != "allow" {
							t.Fatalf("%s pack: decision %s, names %s = %t; want allow with no finding: %.600s", profile, got, row.rule, named, body)
						}
						return
					}
					if !named || got != row.strict {
						t.Fatalf("strict: decision %s, names %s = %t; want %s naming it: %.600s", got, row.rule, named, row.strict, body)
					}
				})
			}
		}
	}
}
