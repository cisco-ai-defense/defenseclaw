// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows are POSIX shell calls and use the POSIX managed peer fixture.

//go:build !windows

package gateway

import (
	"io/fs"
	"os"
	"path/filepath"
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

// TestStdinCodeWrapperStrictSignalReadsMoreSudoForms: strict also names
// CMD-SUDO (a LOW alert) when the elevated shell fed a heredoc is spelled
// with clustered sudo short options, behind env or command under sudo, or
// with doas -s and pkexec <shell>. The default and permissive packs disable
// the rule and still allow with no finding (rel-1-0-6:GAP-0419 review
// round 4, item 4).
func TestStdinCodeWrapperStrictSignalReadsMoreSudoForms(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, wrapper := range []string{
				"sudo -iu root", "sudo -Eu root sh", "sudo env sh", "sudo command sh",
				"sudo env -u FOO bash", "doas -s", "doas -u root sh", "pkexec sh", "pkexec --user root bash",
			} {
				command := wrapper + " <<X\nid\nX"
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + wrapper
				t.Run(name, func(t *testing.T) {
					hook := sudoersHookRow{"claudecode", "wrapper", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": command}))}
					blocked, _, body := postSudoersHook(t, hook, profile, managed)
					got := "allow"
					if blocked {
						got = "block"
					} else if strings.Contains(body, `"action":"alert"`) {
						got = "alert"
					}
					named := strings.Contains(body, "CMD-SUDO:")
					if profile != "strict" {
						if named || got != "allow" {
							t.Fatalf("%s pack: decision %s, names CMD-SUDO = %t; want allow with no finding: %.600s", profile, got, named, body)
						}
						return
					}
					if !named || got != "alert" {
						t.Fatalf("strict: decision %s, names CMD-SUDO = %t; want an alert naming it: %.600s", got, named, body)
					}
				})
			}
		}
	}
}

// TestStdinCodeWrapperBoundedLaneFollowsTheCustomPack: the bounded lane
// that keeps CMD-SUDO on a partial action follows the pack's own
// expression. A copy of the strict pack whose admin narrowed CMD-SUDO to
// sudo -l, or turned it off with an expression other than the literal
// false, names no CMD-SUDO for sudo sh fed a heredoc; the narrowed pack
// still names it for sudo -l (rel-1-0-6:GAP-0419 review round 4, item 5).
func TestStdinCodeWrapperBoundedLaneFollowsTheCustomPack(t *testing.T) {
	for _, pack := range []struct{ name, expression string }{
		{"narrowed", `f.commands.exists(c, c.argv_complete && c.program == 'sudo' && ('-l' in c.argv || '--list' in c.argv))`},
		{"off", `f.tool == 'no-such-tool'`},
	} {
		dir := customStrictSudoPack(t, pack.expression)
		for _, managed := range []bool{false, true} {
			t.Run(pack.name+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
				if pack.name == "narrowed" {
					hook := sudoersHookRow{"claudecode", "wrapper", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "sudo -l"}))}
					if _, _, body := postSudoersHookPack(t, hook, dir, managed); !strings.Contains(body, "CMD-SUDO:") {
						t.Fatalf("narrowed pack: sudo -l names no CMD-SUDO, the pack did not load: %.600s", body)
					}
				}
				for _, command := range []string{"sudo sh <<X\nid\nX", "sudo -s <<\x27X\x27\nid\nX", "cat <<X | sudo sh\nid\nX"} {
					hook := sudoersHookRow{"claudecode", "wrapper", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": command}))}
					blocked, _, body := postSudoersHookPack(t, hook, dir, managed)
					if blocked || strings.Contains(body, "CMD-SUDO:") {
						t.Fatalf("%s pack: %q blocked = %t or names CMD-SUDO: %.600s", pack.name, command, blocked, body)
					}
				}
			})
		}
	}
}

// customStrictSudoPack copies the strict pack and sets the CMD-SUDO
// expression.
func customStrictSudoPack(t *testing.T, expression string) string {
	t.Helper()
	source := filepath.Join(guardrailPoliciesRoot(t), "strict")
	dir := filepath.Join(t.TempDir(), "custom")
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if relative == filepath.Join("rules", "commands.yaml") {
			const strictSudo = "    expression: 'true'\n    pattern: 'a^'\n    title: \"sudo privilege discovery or elevated shell\""
			if strings.Count(string(data), strictSudo) != 1 {
				t.Fatalf("strict CMD-SUDO rule not found in %s", path)
			}
			data = []byte(strings.Replace(string(data), strictSudo,
				"    expression: \""+expression+"\"\n    pattern: 'a^'\n    title: \"sudo privilege discovery or elevated shell\"", 1))
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
