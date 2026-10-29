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

// GAP-2304, GAP-2122 (Windows Git Bash leg, T7W5 rows of GAP-2418): in a
// Git Bash parse the trusted home (and so ~ and $HOME) is a drive path in
// slash form, C:/Users/x. The POSIX resolver left it unresolved because it
// does not start with "/", and the find checks read it as a relative
// path, so an embedded rm/mv/cp/xargs of a DefenseClaw tree and a home
// find that deletes by a state name were allowed with no finding while the
// same rows block on Linux and macOS. The block rows below are the rows
// this fix closes; the allow rows are the benign rows of the same set,
// allowed before and after.
func TestR105GAP2304WindowsGitBashHomeDrivePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Git Bash home drive path is a Windows form")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, file := range []string{"config.yaml", "installer/install.sh", "previous/installer/install.sh",
		"hooks/claude-code-hook.sh", "policies/default.yaml", "receipts/installer.sha256", "logs/gateway.log"} {
		full := filepath.Join(home, ".defenseclaw", filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct {
		id, command string
		block       bool
	}{
		{"T6B10", "find ~ -name config.yaml -delete", true},
		{"T6B11", "find ~ -not -name '*.pyc' -delete", true},
		{"T6B12", "find ~ -name '*.pyc' -or -name '*.yaml' -delete", true},
		{"T6B13", "find ~ \\( -name '*.pyc' -o -name install.sh \\) -delete", true},
		{"T6B14", "find ~ -name '*.pyc' -delete -o -delete", true},
		{"T6B19", "find ~ -path '*/.defenseclaw/*' -delete", true},
		{"T6B6", "find ~ -name '*.pyc' -o -delete", true},
		{"T6B7", "find ~ -name __pycache__ -prune -o -delete", true},
		{"T6B8", "find ~ ! -name '*.pyc' -delete", true},
		{"T6D16", "cd ~/.defenseclaw/hooks && find -exec cat {} \\; -delete", true},
		{"T6D16a", "cd ~/.defenseclaw/hooks && find . -exec cat {} \\; -delete", true},
		{"T6D16b", "cd ~/.defenseclaw/hooks && find -delete", true},
		{"T6D16c", "cd ~/.defenseclaw && rm -rf hooks", true},
		{"T6D16d", "cd ~/.defenseclaw && printf x >> config.yaml", true},
		{"T6D6", "find ~/.defenseclaw/hooks -exec test -f {} \\; -delete", true},
		{"T6P9", "find ~ -name '*.pyc' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6Q1", "find ~ -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6Q10", "find ~/proj -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6Q2", "find ~/.defenseclaw -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6Q7", "find ~/.defenseclaw -name '*.log' -exec rm -rf {} ~/.defenseclaw/hooks +", true},
		{"T6Q8", "find ~ -name '*.orig' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6Q9", "find ~/.defenseclaw -name '*.log' -delete -exec rm -rf ~/.defenseclaw/hooks \\;", true},
		{"T6R1", "find ~/proj -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \\;", true},
		{"T6R11", "echo | xargs rm -rf ~/.defenseclaw/hooks", true},
		{"T6R4", "find /tmp -maxdepth 0 -exec rm -rf ~/.defenseclaw/hooks \\;", true},
		{"T6R6", "find /tmp -maxdepth 0 -exec cp /dev/null ~/.defenseclaw/hooks/claude-code-hook.sh \\;", true},
		{"T6R8", "find /tmp -maxdepth 0 -exec sh -c 'rm -rf ~/.defenseclaw/hooks' \\;", true},
		{"T6X9", "find ~/.defenseclaw/hooks -type f -exec xxd -skip 0 /dev/null {} +", true},
		{"B1", "find ~/.defenseclaw -name '*.log' -mtime +7 -delete", false},
		{"B10", "find ~/.defenseclaw -maxdepth 1 -name '*.tmp' -delete", false},
		{"B2", "find ~/.defenseclaw -name 'gateway.log.*' -delete", false},
		{"B3", "find ~/.defenseclaw -type f -name '*.jsonl' -mtime +14 -delete", false},
		{"B4", "find ~/.defenseclaw/logs -mtime +7 -delete", false},
		{"B5", "find ~/.defenseclaw -name '*.log' -exec rm -f {} +", false},
		{"B6", "find ~/.defenseclaw -name '*\\.log' -delete", false},
		{"B7", "find ~/.defenseclaw -name 'gateway.log.[0-9]*' -delete", false},
		{"B8", "find . -name '*.pyc' -delete", false},
		{"B9", "find ~/.defenseclaw -name '*.log' -print", false},
		{"BL1", "rm -f dclogs/*.log", false},
		{"BL11", "git --work-tree=. clean -fdx", false},
		{"BL12", "git -C ~/proj --work-tree=. clean -fd", false},
		{"BL13", "rsync -avz --exclude node_modules ./ ~/proj2/", false},
		{"BL14", "rsync -a --delete --exclude .git ./ ~/proj2/", false},
		{"BL15", "rsync -a -e ssh ./ host:/x/", false},
		{"BL16", "rm -rf node_modules/*", false},
		{"BL17", "rm -rf proj/build/", false},
		{"BL18", "cp -r dclink/policies/* ~/proj/policies/", false},
		{"BL19", "rsync -a --exclude 'cache/' ~/proj/out ~/.defenseclaw/", false},
		{"BL2", "ls dclink/*", false},
		{"BL20", "rsync -a --link-dest ~/proj/prev/ ~/proj/out ~/.defenseclaw/", false},
		{"BL22", "rm -rf dclogs/*", false},
		{"BL23", "rsync -a --delete ~/proj/out/ ~/proj2/", false},
		{"BL24", "git --work-tree=/tmp/wt --git-dir=/tmp/wt/.git clean -fdx", false},
		{"BL3", "cp dclink/config.yaml /tmp/c.yaml", false},
		{"BL4", "cp -a dclink/. /tmp/dcbackup/", false},
		{"BL5", "rsync -a dclink/ /tmp/dcbk/", false},
		{"BL6", "tar czf /tmp/b.tgz dclink/*", false},
		{"BL7", "cat dclink/logs/*.log", false},
		{"BL8", "rm -rf dclink/logs/old*", false},
		{"BL9", "grep -r foo dclink/*", false},
		{"E4", "find ~/.defenseclaw -name '*.log' -delete -delete", false},
		{"GB0", "chown -R $USER ~/.defenseclaw", false},
		{"GB1", "chmod -R go-rwx ~/.defenseclaw", false},
		{"GB2", "mkdir -p ~/.defenseclaw/logs", false},
		{"GB3", "find ~/.defenseclaw -name '*.log' -exec rm -f {} +", false},
		{"K4", "find ~/.defenseclaw -name 'codex*\\[.log]*' -delete", false},
		{"K6", "find ~/.defenseclaw -name 'co?ex*.log' -delete", false},
		{"L1", "rm -rf dclink/*", false},
		{"L10", "rsync -a /tmp/x/ dclink/", false},
		{"L11", "git -C dclink clean -fdx", false},
		{"L2", "rm -rf ./dclink/hooks/*", false},
		{"L4", "rm -rf dclink/{installer,hooks}", false},
		{"L5", "rm -rf dclink/../.defenseclaw/*", false},
		{"L6", "mv dclink/hooks /tmp/oldhooks", false},
		{"L7", "rm -rf dclink/hook*", false},
		{"L8", "cp -r /tmp/x/* dclink/", false},
		{"L9", "rsync -a --delete /tmp/empty/ dclink/hooks/", false},
		{"R12", "rsync -a --remove-sent-files /tmp/x ~/.defenseclaw/", false},
		{"R14", "git --work-tree=$HOME/.defenseclaw clean -fdx", false},
		{"R15", "git --work-tree ~/.defenseclaw clean -fdx", false},
		{"R16", "git -C ~/.defenseclaw --work-tree=/tmp/wt clean -fdx", false},
		{"R3", "rsync -aT/tmp/te /tmp/x/ ~/.defenseclaw/", false},
		{"R4", "git --work-tree=. -C ~/.defenseclaw clean -fdx", false},
		{"R5", "git --git-dir=/tmp/g/.git --work-tree=. -C ~/.defenseclaw clean -fdx", false},
		{"R6", "git --work-tree hooks -C ~/.defenseclaw clean -fdx", false},
		{"R9", "rsync -a --exclude cache/ /tmp/x/ ~/.defenseclaw/", false},
		{"T6B1", "find ~ -name '*.pyc' -delete", false},
		{"T6B16", "find ~ -name '*.orig' -delete", false},
		{"T6B17", "find ~ -name node_modules -type d -prune -exec rm -rf {} +", false},
		{"T6B2", "find ~ -name __pycache__ -type d -exec rm -rf {} +", false},
		{"T6B3", "find ~ -iname '*.PYC' -delete", false},
		{"T6B4", "find / -xdev -name '*.pyc' -delete", false},
		{"T6B5", "cd ~ && find . -name '*.py[co]' -delete", false},
		{"T6D16B1", "cd ~/.defenseclaw && find . -name '*.log' -delete", false},
		{"T6D16B2", "cd ~/.defenseclaw && cat config.yaml", false},
		{"T6D16B3", "cd ~/project && rm -rf build && printf x > notes.txt", false},
		{"T6D16B4", "find -name '*.tmp' -delete", false},
		{"T6B9", "find ~ -name '*.py' -delete", false},
		{"T6DA1", "find ~/.defenseclaw -name '*.log' -exec cat {} \\; -delete", false},
		{"T6DA2", "find . -name '*.tmp' -exec cat {} \\; -delete", false},
		{"T6DA3", "find /tmp/x -type f -exec cat {} \\; -delete", false},
		{"T6DA4", "find ~/.defenseclaw -name '*.log' -exec grep -q ERROR {} \\; -print", false},
		{"T6DA5", "find ~/.defenseclaw/hooks -type f -exec echo -delete {} \\;", false},
		{"T6DA6", "find ~/.defenseclaw -type f -exec sha256sum {} +", false},
		{"T6DA7", "find ~ -name '*.log' -exec cat {} \\; -delete", false},
		{"T6DA8", "find ~/.defenseclaw/logs -type f -mtime +7 -exec ls -l {} \\; -delete", false},
		{"T6P12", "find ~ -name __pycache__ -exec rm -rf {} +", false},
		{"T6P14", "find ~/proj2 -name __pycache__ -exec rm -rf {} +", false},
		{"T6QA1", "find ~/.defenseclaw -name '*.log' -exec rm -f {} +", false},
		{"T6QA2", "find ~/.defenseclaw/logs -name '*.log' -mtime +7 -execdir rm -f {} \\;", false},
		{"T6R10", "find /tmp -maxdepth 0 -ok rm -rf HOME/.defenseclaw/hooks \\;", false},
		{"T6R2", "find ~/proj -name '*.log' -exec rm -f {} HOME/.defenseclaw/config.yaml \\;", false},
		{"T6R3", "find /tmp -maxdepth 0 -exec rm -rf HOME/.defenseclaw/hooks \\;", false},
		{"T6R5", "find /tmp -maxdepth 0 -exec truncate -s 0 HOME/.defenseclaw/hooks/claude-code-hook.sh \\;", false},
		{"T6R7", "find /tmp -maxdepth 0 -exec mv HOME/.defenseclaw/config.yaml /tmp/c \\;", false},
		{"T6R9", "find /tmp -maxdepth 0 -execdir rm -rf HOME/.defenseclaw/hooks \\;", false},
		{"T6U1", "find ~ -name '*.orig' -delete", false},
		{"T6U2", "find ~ -name '*.pyc' -delete", false},
		{"T6U3", "find ~ -name '*.rej' | xargs rm -f", false},
		{"T6U4", "find ~ -name '*.py' -delete", false},
		{"T6U5", "find ~ -name 'm00042.py' -delete", false},
		{"T6U6", "find ~ -name 'newrule.yaml' -delete", false},
		{"T6XA1", "xxd ~/.defenseclaw/config.yaml | head", false},
		{"T6XA2", "xxd -l 64 ~/.defenseclaw/config.yaml /tmp/out.hex", false},
		{"T6XA3", "find ~/.defenseclaw -type f -exec xxd {} +", false},
		{"T6XA4", "xxd -s -16 ~/.defenseclaw/hooks/claude-code-hook.sh", false},
		{"T6XA5", "xxd build.bin build.hex", false},
		{"T6XA6", "xxd -r -p fw.hex fw.bin", false},
		{"T6XA7", "xxd -i ~/.defenseclaw/config.yaml > /tmp/cfg.h", false},
		{"T6XA8", "find . -name '*.bin' -exec xxd {} \\;", false},
	}
	for _, agent := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, agent, "action", "")
		for _, row := range rows {
			var action string
			var findings []string
			if agent == "claudecode" {
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
					ToolInput: map[string]interface{}{"command": row.command},
				})
				action, findings = resp.Action, resp.Findings
			} else {
				resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
					HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
					ToolInput: map[string]interface{}{"cmd": row.command},
				})
				action, findings = resp.Action, resp.Findings
			}
			blocked := action == guardrailActionBlock
			if blocked != row.block {
				t.Errorf("%s %s %q: blocked=%v, want %v (findings %v)", agent, row.id, row.command, blocked, row.block, findings)
			}
			if row.block && !findingStringHasRuleID(findings, "tamper.detector_state_write") {
				t.Errorf("%s %s %q: blocked without tamper.detector_state_write: %v", agent, row.id, row.command, findings)
			}
		}
	}
}
