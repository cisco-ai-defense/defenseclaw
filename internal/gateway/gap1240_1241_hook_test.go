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
	// The unknown tier: alert in default, permissive and managed, block in
	// strict and managed-strict (unknownTierAction).
	const unknown = "unknown"
	// strictOnly: allow in default, permissive and managed, the unknown tier
	// (a block) in strict and managed-strict: a data program after a PATH
	// change (rel-1-0-10:GAP-1481).
	const strictOnly = "strict-only"
	rows := []row{
		{"H01", "tmp", hd("newgrp", stateWrite), unknown, evaluationLimitRuleID},
		{"H02", "tmp", hd("true && newgrp", stateWrite), unknown, evaluationLimitRuleID},
		{"H03", "tmp", hd("cd /tmp && /tmp/x/wrap sh", stateWrite), unknown, evaluationLimitRuleID},
		{"H04", "tmp", hd("true && PATH=/tmp/x:$PATH cat", stateWrite), strictOnly, evaluationLimitRuleID},
		{"H05b", "tmp", "newgrp <<'EOF' | cat\n" + stateWrite + "\nEOF", unknown, evaluationLimitRuleID},
		{"H06", "tmp", "{ " + hd("newgrp", stateWrite) + "\n}", unknown, evaluationLimitRuleID},
		{"H07", "tmp", "if true; then " + hd("newgrp", stateWrite) + "\nfi", unknown, evaluationLimitRuleID},
		{"H08", "tmp", hd("export PATH=/tmp/x:$PATH; cat", stateWrite), strictOnly, evaluationLimitRuleID},
		{"H09", "tmp", hd("sudo newgrp", stateWrite), unknown, evaluationLimitRuleID},
		{"H10", "tmp", hd("exec newgrp", stateWrite), unknown, evaluationLimitRuleID},
		{"H11", "tmp", hd("nohup /tmp/x/wrap sh", stateWrite), unknown, evaluationLimitRuleID},
		{"H15", "tmp", "( " + hd("newgrp", stateWrite) + "\n)", unknown, evaluationLimitRuleID},
		{"H17", "tmp", hd("false || newgrp", stateWrite), unknown, evaluationLimitRuleID},
		{"H18", "tmp", "newgrp <<'EOF' && true\n" + stateWrite + "\nEOF", unknown, evaluationLimitRuleID},
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
		{"D08", hd("PATH=/usr/local/go/bin:$PATH go run ./cmd", stateWrite), strictOnly, evaluationLimitRuleID},
		{"D09", hd("tee README.md", "To reset, run: rm -rf ~/.defenseclaw"), "allow", ""},
		{"D10", hd("cat > ~/.defenseclaw/notes.txt", "x"), "allow", ""},
		{"D11", hd("PATH=$HOME/.local/bin:$PATH cat > notes.md", "echo x >> ~/.defenseclaw/config.yaml"), strictOnly, evaluationLimitRuleID},
		{"D12", hd("kubectl apply -f -", "kind: ConfigMap"), "allow", ""},
		{"D13", hd("/usr/bin/env bash", "echo hi"), "allow", ""},
		{"D14", hd("cat", stateWrite) + "\nexport PATH=/tmp/x:$PATH", "allow", ""},
		{"D16", "if false; then export PATH=/tmp/x:$PATH; fi; " + hd("cat", stateWrite), "allow", ""},
		{"D16b", "if false; then :; else export PATH=/tmp/x:$PATH; fi; " + hd("cat", stateWrite), strictOnly, evaluationLimitRuleID},
		// GAP-1481: the A/B row at/claude-code/fe1e2e4c686659ba/326, a
		// script written for another host after PATH adds tool folders.
		{"G1481", "cd /tmp && export PATH=~/dc-eh/bin:~/bin:$PATH; cat > t7-99b.sh <<'E'\nset -e\nrm -f /var/lib/defenseclaw-hook-guardian/state.json\nrm -rf ~/.defenseclaw/foreign-hooks-backup\nE\nscp t7-99b.sh dc-rhel:/tmp/ && ssh dc-rhel sudo bash /tmp/t7-99b.sh", strictOnly, evaluationLimitRuleID},
		{"G1481w", "export PATH=/tmp/x:$PATH; env sh <<'E'\n" + stateWrite + "\nE", "not-allow", ""},
		{"G1481s", "export PATH=/tmp/x:$PATH; sh <<'E'\n" + stateWrite + "\nE", "not-allow", ""},
		{"G1481n", "export PATH=/tmp/x:$PATH; newgrp <<'E'\n" + stateWrite + "\nE", unknown, evaluationLimitRuleID},
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
			want := r.action
			rule := r.rule
			switch want {
			case unknown:
				want = "alert"
				if pack.pack == "strict" {
					want = "block"
				}
			case strictOnly:
				want = "block"
				if pack.pack != "strict" {
					want, rule = "allow", ""
				}
			}
			if want == "block" && rule == gap0747StateRule && pack.pack != "strict" {
				// A proven state write is a HIGH alert outside strict (GAP-0747
				// owner tiering 2026-11-15T15:20Z).
				want = "alert"
			}
			if want == "not-allow" && out["action"] == "allow" ||
				want != "not-allow" && out["action"] != want ||
				rule != "" && !gap0526Names(out, rule) {
				t.Errorf("%s %s: want %s %s, got %v", pack.name, r.id, want, r.rule, out)
			}
		}
	}
}
