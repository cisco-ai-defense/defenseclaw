// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// r105StateRow is one agent shell call against the active DefenseClaw
// state and whether it must block (with tamper.detector_state_write).
type r105StateRow struct {
	name, command string
	block         bool
	// routed names the owner seam a row waits for: the shell grammar
	// (internal/actionfacts, classifier) gives the row no path fact yet.
	routed string
}

// r105StateFixture makes the active state the rows act on: config.yaml,
// the saved installer and previous installer, hooks/ and policies/.
func r105StateFixture(t *testing.T) (home, cwd string) {
	t.Helper()
	home, cwd = r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw")
	for _, file := range []string{
		"config.yaml", "installer/install.sh", "previous/installer/install.sh",
		"hooks/claude-code-hook.sh", "policies/default.yaml", "receipts/installer.sha256", "logs/gateway.log",
	} {
		full := filepath.Join(state, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".defenseclaw", "installer"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home, cwd
}

// r105RunStateRows sends each row as a Claude Code Bash call and a Codex
// exec_command call in mode and checks the block.
func r105RunStateRows(t *testing.T, mode, cwd string, rows []r105StateRow) {
	t.Helper()
	r105RunStateRowsChecked(t, mode, cwd, rows, false)
}

// r105RunStateRowsChecked is r105RunStateRows; with quiet, an allowed row
// must also carry no state tamper finding (no alert either).
func r105RunStateRowsChecked(t *testing.T, mode, cwd string, rows []r105StateRow, quiet bool) {
	t.Helper()
	for _, agent := range []string{"claudecode", "codex"} {
		t.Run(agent+"/"+mode, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, agent, mode, "")
			for _, r := range rows {
				t.Run(r.name, func(t *testing.T) {
					if r.routed != "" {
						t.Skip(r.routed)
					}
					var action, reason string
					var findings []string
					if agent == "claudecode" {
						resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
							HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
							ToolInput: map[string]interface{}{"command": r.command},
						})
						action, reason, findings = resp.Action, resp.Reason, resp.Findings
					} else {
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
							ToolInput: map[string]interface{}{"cmd": r.command},
						})
						action, reason, findings = resp.Action, resp.Reason, resp.Findings
					}
					if got := action == guardrailActionBlock; got != r.block {
						t.Fatalf("%s: action=%q want block=%t reason=%q findings=%v", r.command, action, r.block, reason, findings)
					}
					if r.block && !findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Fatalf("%s: blocked without the state tamper finding: %v", r.command, findings)
					}
					if quiet && !r.block && findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Fatalf("%s: allowed row carries the state tamper finding: action=%q findings=%v", r.command, action, findings)
					}
				})
			}
		})
	}
}

// GAP-1773: bash expands a leading $HOME or ${HOME} from the same HOME
// that expands ~, so an agent write to the active state spelled that way
// is the same proven mutation as the ~ spelling and blocks in every mode
// (BALANCED rule 2, LEAD DECISION 10:17). Reads and mentions stay allowed.
// The argument forms block through the state owner; the redirect forms
// wait for the shell grammar seam (routed rows).
func TestR105GAP1773HomeVariableSpellingOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"tilde config (control)", "printf x >> ~/.defenseclaw/config.yaml", true, ""},
		{"$HOME config", "printf x >> $HOME/.defenseclaw/config.yaml", true, "classifier seam GAP-1773: actionfacts leaves a $HOME/${HOME} redirect target unexpanded (Target empty, Expands true)"},
		{"${HOME} config", "printf x >> ${HOME}/.defenseclaw/config.yaml", true, "classifier seam GAP-1773: actionfacts leaves a $HOME/${HOME} redirect target unexpanded (Target empty, Expands true)"},
		{"quoted $HOME config", `printf x >> "$HOME/.defenseclaw/config.yaml"`, true, "classifier seam GAP-1773: actionfacts leaves a $HOME/${HOME} redirect target unexpanded (Target empty, Expands true)"},
		{"$HOME installer", "printf x >> $HOME/.defenseclaw/installer/install.sh", true, "classifier seam GAP-1773: actionfacts leaves a $HOME/${HOME} redirect target unexpanded (Target empty, Expands true)"},
		{"${HOME} installer overwrite", "printf x > ${HOME}/.defenseclaw/installer/install.sh", true, "classifier seam GAP-1773: actionfacts leaves a $HOME/${HOME} redirect target unexpanded (Target empty, Expands true)"},
		{"$HOME rm installer", "rm -f $HOME/.defenseclaw/installer/install.sh", true, ""},
		{"$HOME tee policy", "echo x | tee $HOME/.defenseclaw/policies/default.yaml", true, ""},
		{"read $HOME config", "cat $HOME/.defenseclaw/config.yaml", false, ""},
		{"list $HOME state", "ls -la ${HOME}/.defenseclaw", false, ""},
		{"mention $HOME path", `printf '%s\n' "$HOME/.defenseclaw/config.yaml" > notes.txt`, false, ""},
		{"$HOME log write", "printf x >> $HOME/.defenseclaw/logs/gateway.log", false, ""},
		{"$HOMEX look-alike variable", "printf x >> $HOMEX/.defenseclaw/config.yaml", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRows(t, mode, cwd, rows)
	}
}

// GAP-1774: removing, moving or replacing a whole protected state tree or
// file is a mutation of it: rm -rf of installer/, previous/, hooks/ and
// policies/ (removing hooks/ turns protection off; removing installer/
// breaks rollback), and ln -sf over config.yaml (replaces the file with a
// link). Creating a link elsewhere that points at the state, copying it
// out and the unprotected logs/ tree stay allowed.
func TestR105GAP1774WholeTreeOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"rm -rf installer", "rm -rf ~/.defenseclaw/installer", true, ""},
		{"rm -rf installer slash", "rm -rf ~/.defenseclaw/installer/", true, ""},
		{"rm -rf previous", "rm -rf ~/.defenseclaw/previous", true, ""},
		{"rm -rf previous installer", "rm -rf ~/.defenseclaw/previous/installer", true, ""},
		{"rm -rf hooks", "rm -rf ~/.defenseclaw/hooks", true, ""},
		{"rm -rf policies", "rm -rf ~/.defenseclaw/policies", true, ""},
		{"rm -rf receipts", "rm -rf ~/.defenseclaw/receipts", true, ""},
		{"rm -rf whole state", "rm -rf ~/.defenseclaw", true, ""},
		{"ln -sf over config", "ln -sf /tmp/r105-other ~/.defenseclaw/config.yaml", true, "classifier seam GAP-1774: actionfacts has no ln grammar (effect uncertain, no path fact for the link name)"},
		{"ln -sfn over hooks", "ln -sfn /tmp/r105-other ~/.defenseclaw/hooks", true, "classifier seam GAP-1774: actionfacts has no ln grammar (effect uncertain, no path fact for the link name)"},
		{"rm -rf logs", "rm -rf ~/.defenseclaw/logs", false, ""},
		{"ls installer", "ls -la ~/.defenseclaw/installer", false, ""},
		{"copy installer out", "cp -r ~/.defenseclaw/installer ./installer-copy", false, ""},
		{"link to config elsewhere", "ln -s ~/.defenseclaw/config.yaml ./config-link", false, ""},
		{"project look-alike tree", "rm -rf .defenseclaw/installer", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRows(t, mode, cwd, rows)
	}
}

// GAP-2045: an operand that names the state root or a protected tree
// itself is a state mutation only when it removes or replaces the tree (rm,
// rmdir, an unfiltered find -delete, a move source, a copy or move onto a
// tree name). Creating, touching or chowning the directory, and copying or
// moving a file into the root, are judged by the file reached, so the
// result does not depend on how the destination is spelled. Benign rows
// carry no state finding in observe or action.
func TestR105GAP2045BareStateNamesJudgedByTheFileReached(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	if err := os.WriteFile(filepath.Join(cwd, "notes.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"mkdir -p root", "mkdir -p ~/.defenseclaw", false, ""},
		{"mkdir -p policies", "mkdir -p ~/.defenseclaw/policies", false, ""},
		{"touch root", "touch ~/.defenseclaw", false, ""},
		{"cp into root slash", "cp notes.txt ~/.defenseclaw/", false, ""},
		{"cp into root named", "cp notes.txt ~/.defenseclaw/notes.txt", false, ""},
		{"mv into root slash", "mv notes.txt ~/.defenseclaw/", false, ""},
		{"find log cleanup", "find ~/.defenseclaw -name '*.log' -mtime +7 -delete", false, ""},
		{"chown -R root", "chown -R nobody ~/.defenseclaw", false, ""},
		{"chmod -R root", "chmod -R go-rwx ~/.defenseclaw", false, ""},
		{"ls root", "ls -la ~/.defenseclaw", false, ""},
		// Removing, moving or replacing a tree, and a copy that lands on a
		// protected name, stay blocked.
		{"rmdir hooks", "rmdir ~/.defenseclaw/hooks", true, ""},
		{"find -delete hooks", "find ~/.defenseclaw/hooks -delete", true, ""},
		{"mv hooks away", "mv ~/.defenseclaw/hooks /tmp/r105-h", true, ""},
		{"mv installer aside", "mv ~/.defenseclaw/installer ~/.defenseclaw/installer.bak", true, ""},
		{"mv -t hooks away", "mv -t /tmp ~/.defenseclaw/hooks", true, ""},
		{"mv whole state", "mv ~/.defenseclaw ~/.defenseclaw.old", true, ""},
		{"mv onto hooks", "mv /tmp/r105-evil ~/.defenseclaw/hooks", true, ""},
		{"cp config into root", "cp /tmp/config.yaml ~/.defenseclaw/", true, ""},
		{"cp -r hooks into root", "cp -r /tmp/hooks ~/.defenseclaw/", true, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// GAP-2075: a find -delete is log cleanup only from the state root, with
// every -name/-iname pattern matching no protected name and no OR or
// negation. A start at a protected tree, a pattern that can match a
// protected name, and a time, size or path test alone remove protected
// state and block in every mode.
func TestR105GAP2075FindDeleteOfProtectedStateNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"find hooks name star", "find ~/.defenseclaw/hooks -name '*' -delete", true, ""},
		{"find root name config", "find ~/.defenseclaw -name config.yaml -delete", true, ""},
		{"find root mtime", "find ~/.defenseclaw -mtime +0 -delete", true, ""},
		{"find root size", "find ~/.defenseclaw -size -1G -delete", true, ""},
		{"find root path hooks", "find ~/.defenseclaw -path '*hooks*' -delete", true, ""},
		{"find installer sh", "find ~/.defenseclaw/installer -type f -name '*.sh' -delete", true, ""},
		{"find installer mtime", "find ~/.defenseclaw/installer -type f -mtime +9999 -delete", true, ""},
		{"find root iname yaml", "find ~/.defenseclaw -iname '*.YAML' -delete", true, ""},
		{"find root log or config", "find ~/.defenseclaw -name '*.log' -o -name config.yaml -delete", true, ""},
		{"find root not log", "find ~/.defenseclaw -not -name '*.log' -delete", true, ""},
		// Protected names no hand list holds: connector hooks and rule
		// pack files (pod check 1).
		{"find root codex hook", "find ~/.defenseclaw -name codex-hook.sh -delete", true, ""},
		{"find root codex star", "find ~/.defenseclaw -name 'codex*' -delete", true, ""},
		{"find root copilot hook", "find ~/.defenseclaw -name 'copilot-hook.*' -delete", true, ""},
		{"find root iname codex hook", "find ~/.defenseclaw -iname 'CODEX-HOOK.SH' -delete", true, ""},
		{"find root cognitive pack", "find ~/.defenseclaw -name cognitive.yaml -delete", true, ""},
		{"find root suppressions", "find ~/.defenseclaw -name suppressions.yaml -delete", true, ""},
		{"find root any txt", "find ~/.defenseclaw -type f -name '*.txt' -delete", true, ""},
		// A cleanup marker inside a bracket expression is one character,
		// not literal text (pod check 2).
		{"find root codex bracket log", "find ~/.defenseclaw -name 'codex*[.log]*' -delete", true, ""},
		{"find root cognitive bracket log", "find ~/.defenseclaw -name 'cognitive*[.log]*' -delete", true, ""},
		{"find root iname codex bracket log", "find ~/.defenseclaw -iname 'CODEX*[.LOG]*' -delete", true, ""},
		{"find HOME suppress bracket tmp", "find $HOME/.defenseclaw -name 'suppress*[.tmp]*' -delete", true, ""},
		{"find root unterminated bracket", "find ~/.defenseclaw -name 'codex*[.log' -delete", true, ""},
		// find runs its expression left to right: an action before the
		// name test removes every entry (pod check 3).
		{"find root delete before name log", "find ~/.defenseclaw -delete -name '*.log'", true, ""},
		{"find root type delete before name tmp", "find ~/.defenseclaw -type f -delete -name '*.tmp'", true, ""},
		{"find HOME delete before iname LOG", "find $HOME/.defenseclaw -delete -iname '*.LOG'", true, ""},
		{"find root depth delete before name jsonl", "find ~/.defenseclaw -depth -delete -name '*.jsonl'", true, ""},
		{"find root mtime delete before name log", "find ~/.defenseclaw -mtime +7 -delete -name '*.log'", true, ""},
		// Log cleanup from the root stays allowed with no state finding.
		{"find root log cleanup", "find ~/.defenseclaw -name '*.log' -mtime +7 -delete", false, ""},
		{"find root tmp cleanup", "find ~/.defenseclaw -type f -name '*.tmp' -delete", false, ""},
		{"find root rotated logs", "find ~/.defenseclaw -name 'gateway.log.*' -delete", false, ""},
		{"find root bak cleanup", "find ~/.defenseclaw -name '*.bak' -delete", false, ""},
		{"find root jsonl cleanup", "find ~/.defenseclaw -name '*.jsonl' -mtime +30 -delete", false, ""},
		{"find root escaped log", `find ~/.defenseclaw -name '*\.log' -delete`, false, ""},
		{"find root rotated digit logs", "find ~/.defenseclaw -name 'gateway.log.[0-9]*' -delete", false, ""},
		{"find logs tree", "find ~/.defenseclaw/logs -mtime +7 -delete", false, ""},
		{"find root log cleanup delete twice", "find ~/.defenseclaw -name '*.log' -delete -delete", false, ""},
		{"find root log cleanup then mtime", "find ~/.defenseclaw -name '*.log' -delete -mtime +7", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// GAP-2077: a chmod that gives group or other write on the state root or a
// protected tree is a state mutation (every mode), as the same chmod of a
// file in it already is. Tightening modes and chown stay allowed.
func TestR105GAP2077ChmodGroupOtherWriteOfStateTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"chmod -R 777 root", "chmod -R 777 ~/.defenseclaw", true, ""},
		{"chmod 777 hooks", "chmod 777 ~/.defenseclaw/hooks", true, ""},
		{"chmod o+w policies", "chmod o+w ~/.defenseclaw/policies", true, ""},
		{"chmod g=rwx installer", "chmod g=rwx ~/.defenseclaw/installer", true, ""},
		{"chmod a+w root", "chmod a+w ~/.defenseclaw", true, ""},
		// BSD/macOS symlink options come before the mode (pod check 1); the
		// state owner skips them, the shell grammar seam gives the path fact.
		{"chmod -h 777 hooks", "chmod -h 777 ~/.defenseclaw/hooks", true, "classifier seam GAP-2077: actionfacts chmod grammar does not know the BSD/macOS -h -H -L -P options, so the call gets no path fact"},
		{"chmod -RH 777 root", "chmod -RH 777 ~/.defenseclaw", true, "classifier seam GAP-2077: actionfacts chmod grammar does not know the BSD/macOS -h -H -L -P options, so the call gets no path fact"},
		{"chmod -R -L o+w root", "chmod -R -L o+w ~/.defenseclaw", true, "classifier seam GAP-2077: actionfacts chmod grammar does not know the BSD/macOS -h -H -L -P options, so the call gets no path fact"},
		{"chmod -P g+w hooks", "chmod -R -P g+w ~/.defenseclaw/hooks", true, "classifier seam GAP-2077: actionfacts chmod grammar does not know the BSD/macOS -h -H -L -P options, so the call gets no path fact"},
		// macOS ACL grants of write to another principal.
		{"chmod +a everyone write hooks", `chmod +a "everyone allow write,append" ~/.defenseclaw/hooks`, true, ""},
		{"chmod +a# staff add_file root", `chmod +a# 0 "group:staff allow add_file" ~/.defenseclaw`, true, ""},
		{"chmod +a deny write hooks", `chmod +a "everyone deny write" ~/.defenseclaw/hooks`, false, ""},

		{"chmod 700 hooks", "chmod 700 ~/.defenseclaw/hooks", false, ""},
		{"chmod -R go-rwx root", "chmod -R go-rwx ~/.defenseclaw", false, ""},
		{"chmod u+x hooks", "chmod u+x ~/.defenseclaw/hooks", false, ""},
		{"chmod 755 root", "chmod 755 ~/.defenseclaw", false, ""},
		{"chown -R root", "chown -R nobody ~/.defenseclaw", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

func TestR105GAP2077ChmodModeGroupOtherWrite(t *testing.T) {
	for mode, want := range map[string]bool{
		"777": true, "0775": true, "766": true, "744": false, "700": false, "0755": false, "2770": true,
		"o+w": true, "g+rw": true, "a+w": true, "go=rwx": true, "g=u": true, "u+w,o+w": true,
		"+w": false, "go-w": false, "u+rwx": false, "a-w": false, "=rx": false, "o=r": false,
	} {
		if got := chmodModeAddsGroupOrOtherWrite(mode); got != want {
			t.Errorf("chmod %s: got %t want %t", mode, got, want)
		}
	}
}
