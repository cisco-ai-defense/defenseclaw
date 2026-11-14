// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0570, GAP-0571, GAP-0572 (live detections lane TD on
// dc-rhel, default pack): routine developer calls blocked as an SSH key
// write or alerted as an agent hook config write.
//
//   - GAP-0570: a reader statement that names ~/.ssh (ls, a pipeline of
//     readers) in a call whose other statement is not a known reader (ssh -V)
//     made the folder a write target of the call.
//   - GAP-0571: a link and a rename of plain names after a cd the walk cannot
//     place (cd $W) made every operand of the call an unread link write.
//   - GAP-0572: git checkout -- . matched every registration file name the
//     guard could have under the folder, present or not.
//
// The proven key writes, the link into ~/.ssh and the hook settings write
// keep the verdict they have on rel 9efb4f1799 in every cell.
func TestGAP0570SSHFolderReadsLinksAndCheckoutAreNotKeyOrHookWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	repo := filepath.Join(work, "uuid")
	hooked := filepath.Join(work, "hooked")
	for _, dir := range []string{filepath.Join(repo, ".git"), filepath.Join(hooked, ".git"), filepath.Join(hooked, ".claude"), filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(hooked, ".claude", "settings.json")} {
		if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("W", work)
	const keys, hook = "persistence.ssh_authorized_keys_command", "tamper.agent_hook_config_write"
	allow := map[string]string{"default": "allow", "permissive": "allow", "strict": "allow", "managed": "allow"}
	block := map[string]string{"default": "block", "permissive": "block", "strict": "block", "managed": "block"}
	warn := map[string]string{"default": "alert", "permissive": "alert", "strict": "block", "managed": "alert"}
	rows := []struct {
		name, cwd, command, rule string
		want                     map[string]string
	}{
		{"GAP-0570 list the folder then ssh -V", cwd, "ls -la ~/.ssh | head -5; ssh -V; echo ok", "", allow},
		{"GAP-0570 list then ssh -V", cwd, "ls ~/.ssh; ssh -V", "", allow},
		{"GAP-0570 list and ssh -V", cwd, "ls ~/.ssh && ssh -V", "", allow},
		{"GAP-0570 list then ssh -G", cwd, "ls ~/.ssh; ssh -G localhost", "", allow},
		{"GAP-0571 link and renames after an exported cd", cwd, "export W=$HOME/td/work/default; cd $W && ln -s uuid uuid-link && mv uuid-link uuid-link2 && rm uuid-link2 && echo ok", "", allow},
		{"GAP-0571 link and rename after cd $W", cwd, "cd $W && ln -s uuid uuid-link && mv uuid-link uuid-link2", "", allow},
		{"GAP-0572 checkout of the repo folder", repo, "git checkout -- .", "", allow},
		{"GAP-0572 cd then checkout", cwd, "cd " + repo + " && git checkout -- . && echo reverted", "", allow},
		{"GAP-0572 sed then checkout", repo, "sed -i -e s/a/b/ null.go; git checkout -- .", "", allow},
		// Positive rows: what rel blocks or alerts stays.
		{"keys: append", cwd, "echo marker >> ~/.ssh/authorized_keys", keys, block},
		{"keys: symbolic link then append", cwd, "ln -s ~/.ssh/authorized_keys /tmp/gap570k && echo marker >> /tmp/gap570k", keys, block},
		{"keys: link to .ssh then append", cwd, "ln -s ~/.ssh gap570d && echo marker >> gap570d/authorized_keys", keys, block},
		{"keys: link after cd $W to the keys name then append", cwd, "cd $W && ln -s authorized_keys gap570x && echo marker >> gap570x", keys, block},
		{"keys: relative link up to the keys after cd $W", cwd, "cd $W && ln -s ../../../.ssh/authorized_keys gap570x && mv gap570x gap570y && echo marker >> gap570y", keys, block},
		{"keys: list then the last word", cwd, "ls ~/.ssh/authorized_keys; echo marker >> $_", keys, block},
		{"keys: list, cd in, append", cwd, "ls ~/.ssh; cd ~/.ssh; echo marker >> authorized_keys", keys, block},
		{"keys: reader pipeline then copy", cwd, "cat ~/.ssh/authorized_keys | head; cp notes.txt ~/.ssh/authorized_keys", keys, block},
		{"keys: pipeline into tee", cwd, "ls ~/.ssh | tee ~/.ssh/authorized_keys", keys, block},
		{"keys: read then write the link", cwd, "ls ~/.ssh/authorized_keys; cat keyslink; echo marker >> keyslink", keys, block},
		{"hook: settings write", cwd, "echo {} > ~/.claude/settings.json", hook, warn},
		{"hook: checkout of a folder holding the settings", hooked, "git checkout -- .", hook, warn},
		{"hook: checkout of the settings folder", hooked, "git checkout -- .claude", hook, warn},
		{"hook: checkout naming an absent settings file", repo, "git checkout -- .claude/settings.json", hook, warn},
	}
	for _, row := range rows {
		for _, cell := range []string{"default", "permissive", "strict", "managed"} {
			posture, managed := cell, false
			if cell == "managed" {
				posture, managed = "default", true
			}
			t.Run(fmt.Sprintf("%s %s", cell, row.name), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, row.cwd, "claudecode", posture, managed, row.command)
				if want := row.want[cell]; action != want {
					t.Fatalf("action = %q (rules %v), want %q", action, rules, want)
				}
				if row.rule != "" && !slices.Contains(rules, row.rule) {
					t.Fatalf("rules = %v, want %s", rules, row.rule)
				}
				if row.rule == "" && len(rules) != 0 {
					t.Fatalf("rules = %v, want none", rules)
				}
			})
		}
	}
}
