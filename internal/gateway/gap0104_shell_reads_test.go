// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The GAP-0104 and GAP-0376 rows are judged through the Claude Code and
// Codex hooks, in the five tiers.

// p34fbTiers are the five tiers the hook route judges in.
var p34fbTiers = []struct {
	name, posture string
	managed       bool
}{
	{"default", "default", false},
	{"permissive", "permissive", false},
	{"strict", "strict", false},
	{"managed", "default", true},
	{"managed strict", "strict", true},
}

// p34fbTamperRules are the self-protection rules: a read names none of them.
var p34fbTamperRules = []string{"tamper.detector_state_write", agentHookConfigWriteRuleID, agentHookConfigDisableRuleID}

// p34fbHome is a home with the DefenseClaw state, two hook scripts and the
// Claude Code and Codex hook configs, and a project folder under it.
func p34fbHome(t *testing.T) (home, cwd string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the home fixture needs an unprivileged user")
	}
	home = filepath.Join(t.TempDir(), "home")
	cwd = filepath.Join(home, "proj")
	for _, name := range []string{".defenseclaw/config.yaml", ".defenseclaw/hooks/codex-hook.sh",
		".claude/settings.json", ".codex/config.toml", "proj/README.md"} {
		path := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}

// p34fbJudge returns the verdict of one Bash call through the Claude Code or
// Codex hook in a tier, with the hook client's resolved writes, as a
// per-user gateway judges it.
func p34fbJudge(t *testing.T, connector, posture string, managedInstall bool) func(cwd, command string) (string, []string) {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, connector, "action", "", posture)
	api.health = NewSidecarHealth()
	if managedInstall {
		api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
	}
	return func(cwd, command string) (string, []string) {
		base := context.Background()
		tool, input := "Bash", map[string]any{"command": command}
		if connector == "codex" {
			tool, input = "exec_command", map[string]any{"cmd": command}
		}
		ctx := base
		body := mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "p34fb", "cwd": cwd,
			"tool_name": tool, "tool_input": input})
		if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
			ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
		}
		if managedInstall {
			managedEnterpriseActive.Store(true)
			defer managedEnterpriseActive.Store(false)
		}
		if connector == "codex" {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", SessionID: "p34fb", CWD: cwd,
				ToolName: tool, ToolInput: input})
			return resp.Action, resp.Findings
		}
		resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: "p34fb", CWD: cwd,
			ToolName: tool, ToolInput: input})
		return resp.Action, resp.Findings
	}
}

func p34fbTamperFindings(findings []string) []string {
	var out []string
	for _, f := range findings {
		if slices.ContainsFunc(p34fbTamperRules, func(rule string) bool { return strings.HasPrefix(f, rule+":") || f == rule }) {
			out = append(out, f)
		}
	}
	return out
}

// rel-1-0-10:GAP-0104: a shell call that only reads an agent hook config
// (a hash, cmp, a copy out, a tar archive or a tar extract to standard
// output of it, a hash loop, python code a read grammar proves, a diff of a
// process substitution) named tamper.agent_hook_config_write (default
// alert, strict block) whenever any other part of the call could write:
// the flow net of the registration reader matched every registered name in
// the whole text. A sudo rsync dry run onto the hook folder blocked as a
// state write. In every tier these calls name no self-protection rule and
// are allowed.
func TestGAP0104ShellReadsOfHookConfigsNameNoTamperRule(t *testing.T) {
	home, cwd := p34fbHome(t)
	reads := p34fbReadRows(filepath.ToSlash(filepath.Join(home, ".claude", "settings.json")))
	for _, tier := range p34fbTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			driveReads, _ := p34fbDriveRows(t, home, connector)
			rows := append(slices.Clone(reads), driveReads...)
			t.Run(tier.name+"/"+connector, func(t *testing.T) {
				judge := p34fbJudge(t, connector, tier.posture, tier.managed)
				for _, row := range rows {
					action, findings := judge(cwd, row)
					if tamper := p34fbTamperFindings(findings); len(tamper) != 0 || action != "allow" {
						t.Errorf("%q: action %q, tamper findings %v (all %v), want allow and none", row, action, tamper, findings)
					}
				}
			})
		}
	}
}

// The writes, appends, moves, links, mode changes and redirects into a hook
// config or DefenseClaw state keep their finding: a tamper rule in the
// default, permissive and strict packs, a block in strict. Among them are
// calls that also read the file, and calls whose reader hands the name on
// (ls F | xargs rm, a loop value used after the loop, $(ls F), a while read
// of it), a brace or folder copy and a tar pipe into the home. A managed
// install guards its own state and hook files by machine policy, so these
// per-user paths are judged there as before (no tamper rule at rel either).
func TestGAP0104WritesIntoHookConfigsStillFire(t *testing.T) {
	home, cwd := p34fbHome(t)
	_, driveWrites := p34fbDriveRows(t, home, "claudecode")
	rows := append(p34fbWriteRows(filepath.Join(home, ".claude", "settings.json")), driveWrites...)
	rows = append(rows, p34fbWriteRows(filepath.ToSlash(filepath.Join(home, ".claude", "settings.json")))[7:9]...)
	for _, tier := range p34fbTiers {
		if tier.managed {
			continue
		}
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(tier.name+"/"+connector, func(t *testing.T) {
				judge := p34fbJudge(t, connector, tier.posture, tier.managed)
				for _, row := range rows {
					action, findings := judge(cwd, row)
					if len(p34fbTamperFindings(findings)) == 0 || action == "allow" ||
						tier.posture == "strict" && action != "block" {
						t.Errorf("%q: action %q findings %v, want a tamper rule (strict: block)", row, action, findings)
					}
				}
			})
		}
	}
}

// rel-1-0-10:GAP-0376: a bash here-string read of DefenseClaw state was
// allowed, but its verdict named tamper.detector_state_write (CRITICAL,
// detection-only): the POSIX parse rejects <<<, the pipe twin proved no
// write, and the pack's text match stayed in the findings. The read names
// no state rule in any tier; a here-string write of state still blocks.
func TestGAP0376HereStringReadNamesNoStateRule(t *testing.T) {
	home, cwd := p34fbHome(t)
	// The state as a drive path (C:/Users/x/.defenseclaw/...) is how a
	// native Windows user names it under Git Bash; elsewhere it is the home
	// path itself.
	state := filepath.ToSlash(filepath.Join(home, ".defenseclaw", "config.yaml"))
	reads := []string{
		`python3 - <<< 'import os; print(open(os.path.expanduser("~/.defenseclaw/config.yaml")).read())'`,
		`python3 - <<< "print(open('$HOME/.defenseclaw/config.yaml').read())"`,
		`cat <<< ~/.defenseclaw/config.yaml`,
		`cat <<< ` + state,
	}
	writes := []string{
		`tee ~/.defenseclaw/config.yaml <<< 'x: 1'`,
		`xargs rm -f <<< ~/.defenseclaw/config.yaml`,
		`xargs rm -f <<< ` + state,
		`cat > ~/.defenseclaw/config.yaml <<< 'x: 1'`,
		`xargs rm -rf <<< ~/.defenseclaw/hooks`,
	}
	for _, tier := range p34fbTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(tier.name+"/"+connector, func(t *testing.T) {
				judge := p34fbJudge(t, connector, tier.posture, tier.managed)
				for _, row := range reads {
					action, findings := judge(cwd, row)
					if action == "block" || findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Errorf("%q: action %q findings %v, want no state rule", row, action, findings)
					}
				}
				if tier.managed {
					return
				}
				for _, row := range writes {
					if action, findings := judge(cwd, row); action != "block" || !findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Errorf("%q: action %q findings %v, want a state-write block", row, action, findings)
					}
				}
			})
		}
	}
}

// p34fbDriveRows are copy rows spelled with drive paths, as a native
// Windows user writes them under Git Bash: a backup folder and the hook
// config as C:/Users/x/... (elsewhere the plain absolute path), and on
// Windows also as the MSYS mount /c/Users/x/.... The reads copy a hook
// config out; the writes copy onto one. On Windows the Codex hook reads a
// call that parses as PowerShell in that dialect (Codex runs PowerShell
// there; selectWindowsShellDialectReading), where cp -p is Copy-Item with an
// ambiguous -p that copies nothing: the drive-path read is a Git Bash read
// (Claude Code) on Windows, and a read of both connectors elsewhere.
func p34fbDriveRows(t *testing.T, home, connector string) (reads, writes []string) {
	t.Helper()
	bak := filepath.ToSlash(filepath.Join(t.TempDir(), "bak"))
	settings := filepath.ToSlash(filepath.Join(home, ".claude", "settings.json"))
	if runtime.GOOS != "windows" || connector == "claudecode" {
		reads = []string{`mkdir -p ` + bak + `; cp -p ~/.claude/settings.json ` + bak + `/settings.json; cp -p ~/.codex/config.toml ` + bak + `/`}
	}
	writes = []string{`cp -p /tmp/gap0104-x ` + settings, `cp -p ~/.codex/config.toml ` + settings}
	if runtime.GOOS == "windows" {
		reads = append(reads, `cp -p ~/.claude/settings.json `+p34fbMSYS(bak)+`/settings.json`)
		writes = append(writes, `cp -p /tmp/gap0104-x `+p34fbMSYS(settings), `cp -p ~/.codex/config.toml `+p34fbMSYS(settings))
	}
	return reads, writes
}

// p34fbMSYS spells a drive path C:/x as its MSYS mount /c/x.
func p34fbMSYS(path string) string {
	return "/" + strings.ToLower(path[:1]) + path[2:]
}

func p34fbReadRows(settings string) []string {
	return []string{
		`sudo -u testuser -H shasum -a 256 ~/.defenseclaw/config.yaml ~/.codex/config.toml; echo done > /tmp/gap0104-log`,
		`cmp -s /tmp/gap0104-before.json ~/.claude/settings.json && echo SAME > /tmp/gap0104-cmp`,
		`mkdir -p /tmp/gap0104-bak; cp -p ~/.claude/settings.json /tmp/gap0104-bak/settings.json; cp -p ~/.codex/config.toml /tmp/gap0104-bak/config.toml`,
		`s=/tmp/gap0104-bak; tar -C ~ -cpf "$s/pre.tar" .defenseclaw/config.yaml .claude/settings.json .codex/config.toml; chmod 600 "$s/pre.tar"`,
		`tar -xOf /tmp/gap0104.tar .codex/config.toml | sha256sum`,
		`for p in .claude/settings.json .codex/config.toml; do shasum -a 256 ~/$p; done >> /tmp/gap0104-loop.txt`,
		"python3 - <<'PY'\nimport json\nfrom pathlib import Path\nprint(json.loads(Path('" + settings + "').read_text()).get('hooks'))\nPY\necho ok > /tmp/gap0104-py",
		`python3 -c 'import json; print(json.load(open("` + settings + `")))' | head`,
		`diff <(cat ~/.codex/config.toml) /tmp/gap0104-bak/config.toml > /tmp/gap0104-diff.txt`,
		`sha256sum ~/.claude/settings.json ~/.codex/config.toml > /tmp/gap0104-hashes.txt`,
		`stat -c '%a %n' ~/.codex/config.toml > /tmp/gap0104-stat.raw`,
		`sudo rsync -anrc --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`,
	}
}

func p34fbWriteRows(settings string) []string {
	return []string{
		`sha256sum ~/.codex/config.toml; echo '{}' > ~/.claude/settings.json`,
		`cp /tmp/gap0104-bak/config.toml ~/.codex/config.toml && sha256sum ~/.codex/config.toml`,
		`echo x | tee -a ~/.codex/config.toml > /dev/null`,
		`mv ~/.codex/config.toml /tmp/gap0104-moved.toml`,
		`ln -sf /dev/null ~/.claude/settings.json`,
		`chmod 666 ~/.claude/settings.json`,
		`for p in ~/.claude/settings.json; do cp /dev/null "$p"; done`,
		"python3 - <<'PY'\nopen('" + settings + "', 'w').write('')\nPY",
		`python3 -c 'open("` + settings + `", "w").write("")' && echo ok > /tmp/gap0104-py`,
		`rsync -a /tmp/gap0104-src/config.toml ~/.codex/config.toml`,
		`tar -cf ~/.codex/config.toml /tmp/gap0104-src`,
		`sha256sum ~/.defenseclaw/config.yaml; echo x > ~/.defenseclaw/config.yaml`,
		`cp /tmp/gap0104-x ~/.defenseclaw/hooks/codex-hook.sh`,
		`sudo rsync -a --delete /tmp/gap0104-src/ ~/.defenseclaw/hooks/`,
		`find ~/.defenseclaw/hooks -type f -exec sh -c 'for f do : > "$f"; done' sh {} +`,
		// A reader that hands the name on, a loop value used after the
		// loop, brace and folder copies, a tar pipe and a substitution.
		`ls ~/.claude/settings.json | xargs rm -f; echo gone > /tmp/gap0104-x`,
		`sha256sum ~/.claude/settings.json > /tmp/gap0104-h; cut -d' ' -f3 /tmp/gap0104-h | xargs truncate -s0`,
		`for p in ~/.claude/settings.json; do cat "$p"; done; : > "$p"`,
		`cat ~/.claude/settings.json > /dev/null; cp -p ~/.claude/settings.json{.bak,}`,
		`sha256sum /tmp/gap0104-src/settings.json && cp /tmp/gap0104-src/settings.json ~/.claude/`,
		`cat ~/.claude/settings.json; cp -r /tmp/gap0104-evil/.claude ~/ && echo ok > /tmp/gap0104-x`,
		`tar -C /tmp/gap0104-evil -cf - .claude/settings.json | tar -C ~ -xf -`,
		`cat ~/.claude/settings.json; cp /dev/null "$(ls ~/.claude/settings.json)"`,
		`cp -l ~/.claude/settings.json /tmp/gap0104-l && echo '{}' > /tmp/gap0104-l`,
		`cat ~/.claude/settings.json; sudo tar -xf /tmp/gap0104.tar -C ~ .claude/settings.json`,
		`tar -xf /tmp/gap0104.tar -C ~ .claude/settings.json; sha256sum ~/.claude/settings.json`,
		`f=~/.claude/settings.json; sha256sum "$f"; : > "$f"`,
		`cmp -s /tmp/a ~/.claude/settings.json || cp /tmp/a ~/.claude/settings.json`,
		`sha256sum ~/.claude/settings.json; sed -i s/a/b/ ~/.claude/settings.json`,
		`while read -r f; do : > "$f"; done <<< "$(ls ~/.claude/settings.json)"`,
	}
}
