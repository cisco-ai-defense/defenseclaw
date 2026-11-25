// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hardP2Verdict is the verdict of one Bash/shell call on a connector route.
func hardP2Verdict(t *testing.T, api *APIServer, route, cwd, command string) (string, string) {
	t.Helper()
	if route == "claudecode" {
		resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{HookEventName: "PreToolUse",
			SessionID: "det111-hard-p2", CWD: cwd, ToolName: "Bash", ToolInput: map[string]interface{}{"command": command}})
		return resp.Action, resp.Severity
	}
	resp := api.evaluateCodexHook(t.Context(), codexHookRequest{HookEventName: "PreToolUse", ToolName: "shell",
		CWD: cwd, ToolInput: map[string]interface{}{"command": command}})
	return resp.Action, resp.Severity
}

// TestDET111KnownProtectedWriteIsThePlainSpelling (DET111 ruling
// 2026-11-23 on GAP-1478, GAP-1500, GAP-0662 var6b, GAP-0506 writer list): a
// Known write or append to an exact member of a restricted set, by any
// program the program table models with a write role, gets the verdict the
// plain cp spelling gets on that member in all five tiers on both routes. At
// ad6ab569dd these spellings were allowed: only the reviewed program list
// (cp, tee, redirection, ...) reached a verdict. A benign write of the same
// programs stays allowed.
func TestDET111KnownProtectedWriteIsThePlainSpelling(t *testing.T) {
	home := t.TempDir()
	for _, f := range []string{".ssh/authorized_keys", ".aws/credentials", ".claude/settings.json", ".codex/hooks.json",
		".defenseclaw/config.yaml", "proj/notes.txt", "proj/data.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	py := func(mode string) string {
		return `python3 -c "open('{t}','` + mode + `').write('x')"`
	}
	writers := map[string]string{
		"sort -o":       "sort -o {t} /tmp/x",
		"rsync log":     "rsync -n --log-file={t} /tmp/a /tmp/b",
		"sed w":         "sed -n 'w {t}' /dev/null",
		"python -c":     py("a"),
		"python here":   `python3 - <<< "open('{t}','w').write('x')"`,
		"watch python":  `watch -n1 'python3 -c "open(\"{t}\",\"a\").write(\"x\")"'`,
		"plain control": "cp /tmp/x {t}",
	}
	targets := map[string][]string{
		".claude/settings.json":    {"sort -o", "rsync log", "sed w", "python here", "watch python"},
		".codex/hooks.json":        {"sort -o"},
		".defenseclaw/config.yaml": {"rsync log", "sed w", "python here", "watch python"},
		".aws/credentials":         {"rsync log", "sed w", "python -c", "python here", "watch python"},
		".git-credentials":         {"python -c"},
		".npmrc":                   {"python -c"},
		".kube/config":             {"python -c"},
		".docker/config.json":      {"python -c"},
	}
	benign := []string{
		"sort -o " + home + "/proj/data.txt " + home + "/proj/notes.txt",
		"rsync -av --log-file=" + home + "/proj/rs.log " + home + "/proj/ /tmp/bk/",
		"sed -n 'w /tmp/o.txt' " + home + "/proj/notes.txt",
		`python3 -c "open('out.txt','w').write('x')"`,
		`python3 -c "print(open('` + home + `/.claude/settings.json').read())"`,
	}
	useDefaultEffectsLane(t)
	for _, tier := range boundedTestTiers {
		for _, route := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, route, tier.posture, tier.managed, tier.tier)
			for target, names := range targets {
				member := filepath.Join(home, target)
				wantAction, wantSev := hardP2Verdict(t, api, route, home, strings.ReplaceAll(writers["plain control"], "{t}", member))
				if wantAction == "allow" && tier.name == "default" {
					t.Fatalf("%s %s: plain control on %s allows: the control is void", tier.name, route, target)
				}
				for _, name := range names {
					action, sev := hardP2Verdict(t, api, route, home, strings.ReplaceAll(writers[name], "{t}", member))
					if action != wantAction || sev != wantSev && (target != ".defenseclaw/config.yaml" || sev != "HIGH") {
						t.Errorf("%s %s %s on %s: %s/%s, plain spelling %s/%s", tier.name, route, name, target, action, sev, wantAction, wantSev)
					}
				}
			}
			for _, command := range benign {
				if action, _ := hardP2Verdict(t, api, route, home+"/proj", command); action != "allow" {
					t.Errorf("%s %s benign %q: %s, want allow", tier.name, route, command, action)
				}
			}
		}
	}
}
