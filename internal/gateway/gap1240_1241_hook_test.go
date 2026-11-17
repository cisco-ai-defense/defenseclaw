// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These are the s7-g1182rev H, W, O and D rows, through Claude Code
// PreToolUse in each of the five policy tiers. The shell examples stay here
// so a future parser change cannot silently drop the owning command.
func TestGAP1240GAP1241ReviewRowsOnClaudeHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	relHome := strings.TrimPrefix(home, "/")
	const stateWrite = ": >> ~/.defenseclaw/config.yaml"
	hd := func(prefix, body string) string { return prefix + " <<'EOF'\n" + body + "\nEOF" }
	type row struct{ id, cwd, command, action, rule string }
	unknown := "alert"
	rows := []row{
		{"H02", "tmp", hd("true && newgrp", stateWrite), unknown, parseFailureRuleID},
		{"H03", "tmp", hd("cd /tmp && /tmp/x/wrap sh", stateWrite), unknown, parseFailureRuleID},
		{"H04", "tmp", hd("true && PATH=/tmp/x:$PATH cat", stateWrite), unknown, parseFailureRuleID},
		{"H05b", "tmp", "newgrp <<'EOF' | cat\n" + stateWrite + "\nEOF", unknown, parseFailureRuleID},
		{"H06", "tmp", "{ " + hd("newgrp", stateWrite) + "\n}", unknown, parseFailureRuleID},
		{"H07", "tmp", "if true; then " + hd("newgrp", stateWrite) + "\nfi", unknown, parseFailureRuleID},
		{"H08", "tmp", hd("export PATH=/tmp/x:$PATH; cat", stateWrite), unknown, parseFailureRuleID},
		{"H09", "tmp", hd("sudo newgrp", stateWrite), unknown, parseFailureRuleID},
		{"H10", "tmp", hd("exec newgrp", stateWrite), unknown, parseFailureRuleID},
		{"H11", "tmp", hd("nohup /tmp/x/wrap sh", stateWrite), unknown, parseFailureRuleID},
		{"H15", "tmp", "( " + hd("newgrp", stateWrite) + "\n)", unknown, parseFailureRuleID},
		{"H17", "tmp", hd("false || newgrp", stateWrite), unknown, parseFailureRuleID},
		{"H18", "tmp", "newgrp <<'EOF' && true\n" + stateWrite + "\nEOF", unknown, parseFailureRuleID},
		{"W02", "tmp", "chroot / sh -c ': >> " + relHome + "/.defenseclaw/config.yaml'", "block", "tamper.detector_state_write"},
		{"W02b", "home", "chroot / sh -c ': >> " + relHome + "/.defenseclaw/config.yaml'", "block", "tamper.detector_state_write"},
		{"W10", "tmp", "nsenter --target=1 --wd=/ sh -c ': >> " + relHome + "/.defenseclaw/config.yaml'", "block", "tamper.detector_state_write"},
		{"W17", "tmp", "nsenter --target=1 -w sh -c ': >> .defenseclaw/config.yaml'", "not-allow", ""},
		{"W18", "tmp", "nsenter --target=1 -r sh -c ': >> .defenseclaw/config.yaml'", "not-allow", ""},
	}
	for _, control := range []struct{ id, command string }{
		{"O01", "timeout 60 flock /tmp/l make test"},
		{"O02", "chroot / ls /"},
		{"O03", "nsenter -t 1 -m -- ls /"},
		{"O04", "flock /tmp/l git status"},
		{"O05", "taskset -c 0 python3 bench.py"},
		{"O06", "nice -n 10 ionice -c3 tar czf out.tgz src"},
		{"O07", "stdbuf -oL tail -n 5 log.txt"},
		{"O08", "xargs -n1 echo < list.txt"},
		{"O09", "sudo -u postgres psql -c 'select 1'"},
		{"O10", "sudo -n -u testuser bash -lc 'command -v node; node --version'"},
		{"O11", "setsid nohup sh -c 'sleep 1'"},
		{"O12", "flock /tmp/l sh -c 'go test ./...'"},
		{"O13", "timeout 5 sudo bash -c 'apt-get update'"},
		{"O14", "sudo -u testuser -H bash -lc 'cd ~/proj; ls'"},
		{"O15", "chroot /srv/root /bin/sh -c 'apt-get install -y curl'"},
		{"O16", "unshare -r sh -c 'id'"},
		{"O17", "sudo bash -c 'systemctl restart nginx'"},
		{"O18", "sudo -u testuser bash -lc 'sha256sum ~/.defenseclaw/config.yaml'"},
		{"O19", "nsenter -t 1 -m -u -i -n -p -- sh -c 'ls /'"},
		{"O20", "flock -n /tmp/l timeout 30 nice -n 5 python3 -m pytest -q"},
	} {
		rows = append(rows, row{control.id, "tmp", control.command, "allow", ""})
	}
	for _, control := range []struct{ id, command, action, rule string }{
		{"D01", hd("cat > notes.md", "set x in ~/.defenseclaw/config.yaml"), "allow", ""},
		{"D02", hd("python3 -", "open('x','w').write('1')"), "allow", ""},
		{"D03", hd("git commit -F -", "fix: defenseclaw config write"), "allow", ""},
		{"D04", hd("gh pr create --title x --body-file -", "Run echo x >> ~/.defenseclaw/config.yaml to reproduce"), "allow", ""},
		{"D05", hd("PATH=$HOME/go/bin:$PATH cat", "ordinary text"), "allow", ""},
		{"D06", hd("sh", "echo hi"), "allow", ""},
		{"D07", hd("bash", "sudo apt-get install -y jq"), "allow", ""},
		{"D08", hd("PATH=/usr/local/go/bin:$PATH go run ./cmd", stateWrite), "alert", parseFailureRuleID},
		{"D09", hd("tee README.md", "To reset, run: rm -rf ~/.defenseclaw"), "allow", ""},
		{"D10", hd("cat > ~/.defenseclaw/notes.txt", "x"), "allow", ""},
		{"D11", hd("PATH=$HOME/.local/bin:$PATH cat > notes.md", "echo x >> ~/.defenseclaw/config.yaml"), "alert", parseFailureRuleID},
		{"D12", hd("kubectl apply -f -", "kind: ConfigMap"), "allow", ""},
		{"D13", hd("/usr/bin/env bash", "echo hi"), "allow", ""},
		{"D14", hd("cat", stateWrite) + "\nexport PATH=/tmp/x:$PATH", "allow", ""},
	} {
		rows = append(rows, row{control.id, "tmp", control.command, control.action, control.rule})
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		for i, r := range rows {
			cwd := root
			if r.cwd == "home" {
				cwd = home
			}
			out := gap0437Hook(t, hook, cwd, fmt.Sprintf("%s-%d", pack.name, i), r.command)
			if r.action == "not-allow" && out["action"] == "allow" ||
				r.action != "not-allow" && out["action"] != r.action ||
				r.rule != "" && !gap0526Names(out, r.rule) {
				t.Errorf("%s %s: want %s %s, got %v", pack.name, r.id, r.action, r.rule, out)
			}
		}
	}
}
