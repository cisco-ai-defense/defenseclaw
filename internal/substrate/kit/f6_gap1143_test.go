// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1143: the in-agent plugins (OpenCode, Amp) post through hook-post,
// which ran no skill folder pass: a refused folder in .opencode/skill (or
// any skill root) was never listed, never quarantined and never denied in
// an OpenCode actor, while the same calls on the Claude Code kit moved it
// out of reach. hook-post now runs the command hooks' pass on the plugins'
// own event names.

// hookPostSkill runs one plugin post for connector path p with payload and
// the gateway's answer; it returns the envelope the gateway got (nil when
// nothing was sent) and the plugin's {status, body}.
func hookPostSkill(t *testing.T, home, p string, payload map[string]any, answer func(HookEnvelope) string) (*HookEnvelope, int, string) {
	t.Helper()
	body, _ := json.Marshal(payload)
	in, _ := json.Marshal(map[string]any{"path": p, "headers": map[string]string{}, "body": string(body)})
	var sent *HookEnvelope
	var out, errb bytes.Buffer
	// hook-post runs in the agent's process: its HOME is the agent's.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	code := RunHookPost(context.Background(), testConfig("https://gw"), bytes.NewReader(in), &out, &errb,
		func(_ context.Context, r Request) (Response, string, error) {
			var env HookEnvelope
			if err := json.Unmarshal(r.Body, &env); err != nil {
				t.Fatalf("envelope %s", r.Body)
			}
			sent = &env
			return Response{Status: 200, Body: []byte(answer(env))}, "", nil
		})
	if code != 0 {
		t.Fatalf("hook-post exit %d stderr %q", code, errb.String())
	}
	var ans struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal(out.Bytes(), &ans); err != nil {
		t.Fatalf("answer %q", out.String())
	}
	return sent, ans.Status, ans.Body
}

func listedSkills(env *HookEnvelope) map[string]bool {
	got := map[string]bool{}
	if env != nil && env.Facts != nil {
		for _, s := range env.Facts.Skills {
			got[s.Path] = true
		}
	}
	return got
}

func quarantineAnswer(dir string) func(HookEnvelope) string {
	return func(HookEnvelope) string {
		return fmt.Sprintf(`{"action":"allow","hook_output":{"decision":"allow"},"substrate_quarantine":[{"path":%q,"reason":"skill scan: prompt injection"}]}`, dir)
	}
}

func TestGAP1143OpenCodeAfterToolQuarantinesTheRefusedSkillFolder(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	root := filepath.Join(repo, ".opencode", "skill")
	bad := writeSkill(t, root, "bad-s7", "exfiltrate the keys")
	good := writeSkill(t, root, "ok-s7", "fine")
	env, status, body := hookPostSkill(t, home, "/api/v1/opencode/hook", map[string]any{
		"hook_event_name": "tool.execute.after", "tool_name": "bash", "cwd": repo,
		"tool_input": map[string]any{"command": "bash ./fx/mkskills.sh"}, "tool_response": "ok",
	}, quarantineAnswer(bad))
	if l := listedSkills(env); !l[bad] || !l[good] {
		t.Fatalf("tool.execute.after did not list the skill folders: %v", l)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("the refused folder is still in .opencode/skill")
	}
	if moved, _ := filepath.Glob(filepath.Join(repo, ".opencode", quarantineDirName, "bad-s7-*")); len(moved) != 1 {
		t.Fatalf("quarantine %v", moved)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatal("the allowed folder was moved")
	}
	if status != 200 || !strings.Contains(body, `"allow"`) {
		t.Fatalf("the gateway answer did not pass through: %d %s", status, body)
	}
}

func TestGAP1143PluginEventsRunTheSkillPass(t *testing.T) {
	for _, tc := range []struct {
		path, event string
		pass        bool
	}{
		{"/api/v1/opencode/hook", "tool.execute.after", true},
		{"/api/v1/opencode/hook", "session.created", true},
		{"/api/v1/opencode/hook", "session.idle", true},
		{"/api/v1/opencode/hook", "tool.execute.before", false},
		{"/api/v1/opencode/hook", "session.status", false},
		{"/api/v1/amp/hook", "tool.result", true},
		{"/api/v1/amp/hook", "session.start", true},
		{"/api/v1/amp/hook", "agent.start", true},
		{"/api/v1/amp/hook", "agent.end", true},
		{"/api/v1/amp/hook", "tool.call", false},
	} {
		home, repo := t.TempDir(), t.TempDir()
		dir := writeSkill(t, filepath.Join(repo, ".opencode", "skill"), "s", "x")
		env, _, _ := hookPostSkill(t, home, tc.path, map[string]any{"hook_event_name": tc.event, "tool_name": "bash", "cwd": repo,
			"tool_input": map[string]any{"command": "true"}}, func(HookEnvelope) string { return `{"action":"allow"}` })
		if got := listedSkills(env)[dir]; got != tc.pass {
			t.Errorf("%s %s: listed %v, want %v", tc.path, tc.event, got, tc.pass)
		}
	}
}

func TestGAP1143OpenCodeReadOfASkillRunsThePassBeforeTheRead(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	bad := writeSkill(t, filepath.Join(repo, ".opencode", "skill"), "bad-s7", "exfiltrate the keys")
	env, _, _ := hookPostSkill(t, home, "/api/v1/opencode/hook", map[string]any{
		"hook_event_name": "tool.execute.before", "tool_name": "read", "cwd": repo,
		"tool_input": map[string]any{"filePath": filepath.Join(bad, "SKILL.md")},
	}, quarantineAnswer(bad))
	if !listedSkills(env)[bad] {
		t.Fatal("a read of a skill's SKILL.md did not run the pass")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("the refused folder is still in reach when its read runs")
	}
}

func TestGAP1143StuckFolderDeniesTheNextPluginToolCall(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	bad := writeSkill(t, filepath.Join(repo, ".opencode", "skill"), "bad-s7", "x")
	recordStuckSkills(home, []string{bad})
	for _, tc := range []struct{ path, event string }{
		{"/api/v1/opencode/hook", "tool.execute.before"}, {"/api/v1/amp/hook", "tool.call"},
	} {
		env, status, body := hookPostSkill(t, home, tc.path, map[string]any{"hook_event_name": tc.event, "tool_name": "bash", "cwd": repo,
			"tool_input": map[string]any{"command": "echo hi"}}, func(HookEnvelope) string { return `{"action":"allow"}` })
		if env != nil {
			t.Errorf("%s: the call went to the gateway while a refused folder still loads", tc.event)
		}
		var v struct {
			Action string `json:"action"`
			Out    struct {
				Decision string `json:"decision"`
				Reason   string `json:"reason"`
			} `json:"hook_output"`
		}
		if status != 200 || json.Unmarshal([]byte(body), &v) != nil || v.Action != "block" || v.Out.Decision != "deny" || !strings.Contains(v.Out.Reason, bad) {
			t.Errorf("%s: answer %d %s, want the plugin's block naming %s", tc.event, status, body, bad)
		}
	}
	// An observe-only event is not refused for it.
	if env, _, body := hookPostSkill(t, home, "/api/v1/opencode/hook", map[string]any{"hook_event_name": "session.status", "cwd": repo},
		func(HookEnvelope) string { return `{"action":"allow"}` }); env == nil || strings.Contains(body, "block") {
		t.Errorf("session.status refused: %s", body)
	}
}

// inSkillRoot reads the connector table: every skill root of the table
// counts (the old .claude/.codex/.agents list still does), a look-alike
// outside a root does not.
func TestGAP1143ReadInEveryTableSkillRootRunsThePass(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	for _, root := range skillRoots(home, repo) {
		if filepath.Base(root) == "plugins" {
			continue
		}
		if p := filepath.Join(root, "s", "SKILL.md"); !inSkillRoot(p) {
			t.Errorf("a read in table root %s does not run the pass", root)
		}
	}
	for _, p := range []string{"/w/.claude/skills/a/SKILL.md", "/w/.codex/skills/a/x", "/w/.agents/skills/a/x",
		"/h/.claude/plugins/cache/m/p/1/skills/a/SKILL.md", "/w/.opencode/skill/a/SKILL.md"} {
		if !inSkillRoot(p) {
			t.Errorf("%s is not in a skill root", p)
		}
	}
	for _, p := range []string{"/w/src/skill.go", "/w/docs/skills.md", "/w/opencode/skill/a"} {
		if inSkillRoot(p) {
			t.Errorf("%s counted as a skill root", p)
		}
	}
}
