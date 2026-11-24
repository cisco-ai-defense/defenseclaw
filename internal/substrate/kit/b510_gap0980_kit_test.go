//go:build linux

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

// SKILLSCAN-B10, GAP-0980 kit side (RV5-A): a managed pass whose answer
// never came records the folders it attached; every later PreToolUse call,
// whatever the tool and connector, runs the pass again, and is refused when
// that pass goes unanswered too, until the gateway gives a verdict. Red at
// 39cdfbc4fd (the next Bash/shell call runs no pass and is forwarded).
func TestB510KitLostPassAnswerHolds(t *testing.T) {
	for _, c := range []struct{ connector, root, tool, failMode string }{
		{"claudecode", ".claude/skills", "Bash", "closed"},
		{"codex", ".codex/skills", "shell", "closed"},
		{"claudecode", ".claude/skills", "Bash", "open"},
		{"codex", ".codex/skills", "shell", "open"},
	} {
		t.Run(c.connector+"/fail_mode_"+c.failMode, func(t *testing.T) {
			home, repo := t.TempDir(), t.TempDir()
			dir := writeSkill(t, filepath.Join(home, c.root), "slow", "x")
			cfg := testConfig("https://gw")
			cfg.Managed = true
			cfg.FailMode = c.failMode
			lost := func(_ context.Context, r Request) (Response, string, error) {
				return Response{}, "", fmt.Errorf("%w: context deadline exceeded", ErrUnreachable)
			}
			post := `{"hook_event_name":"PostToolUse","tool_name":"` + c.tool + `","tool_input":{"command":"cp -r /tmp/slow ~/` + c.root + `/"},"tool_response":{},"cwd":"` + repo + `"}`
			pre := `{"hook_event_name":"PreToolUse","tool_name":"` + c.tool + `","tool_input":{"command":"ls"},"cwd":"` + repo + `"}`
			run := func(payload string, send func(context.Context, Request) (Response, string, error)) (int, string, []string) {
				var out, errb bytes.Buffer
				var listed []string
				code := RunHook(context.Background(), HookOptions{Connector: c.connector, Config: cfg, Home: home,
					Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
					Send: func(ctx context.Context, r Request) (Response, string, error) {
						var env HookEnvelope
						_ = json.Unmarshal(r.Body, &env)
						if env.Facts != nil {
							for _, s := range env.Facts.Skills {
								listed = append(listed, s.Path)
							}
						}
						return send(ctx, r)
					}})
				return code, out.String() + errb.String(), listed
			}
			run(post, lost)
			if got := skillsPendingInReach(home); len(got) != 1 || got[0] != dir {
				t.Fatalf("unanswered managed pass: record %v, want [%s]", got, dir)
			}
			// The next call (a plain shell call) runs the pass; unanswered too: refused.
			code, out, listed := run(pre, lost)
			if len(listed) == 0 || (c.connector == "claudecode" && code != 2 && !strings.Contains(out, `"deny"`)) || !strings.Contains(out, `"slow" is still being scanned; DefenseClaw refuses tool calls until the scan finishes`) {
				t.Fatalf("PreToolUse after a lost pass: listed=%v out=%q", listed, out)
			}
			// The gateway holds it (403 substrate_pending): the record stays.
			fp := ""
			held := func(_ context.Context, r Request) (Response, string, error) {
				var env HookEnvelope
				_ = json.Unmarshal(r.Body, &env)
				for _, s := range env.Facts.Skills {
					fp = s.FP
				}
				b, _ := json.Marshal(map[string]any{"action": "block", "message": "held", SkillPendingField: []map[string]string{{"path": dir, "fp": fp}}})
				return Response{Status: 403, Body: b}, "", nil
			}
			if _, _, listed = run(pre, held); len(listed) == 0 || len(skillsPendingInReach(home)) != 1 {
				t.Fatalf("held: listed=%v record=%v", listed, skillsPendingInReach(home))
			}
			// The verdict comes (scanned): the record goes, and a plain call runs no pass again.
			scanned := func(_ context.Context, r Request) (Response, string, error) {
				b, _ := json.Marshal(map[string]any{"action": "allow", "substrate_scanned": []map[string]string{{"path": dir, "fp": fp, "receipt": "r"}}})
				return Response{Status: 200, Body: b}, "", nil
			}
			run(pre, scanned)
			if got := skillsPendingInReach(home); len(got) != 0 {
				t.Fatalf("after the verdict: record %v", got)
			}
			if _, _, listed = run(pre, scanned); len(listed) != 0 {
				t.Fatalf("no record: a plain PreToolUse must run no pass, listed %v", listed)
			}
			if _, err := os.Stat(skillPendingPath(home)); !os.IsNotExist(err) {
				t.Fatalf("record file left: %v", err)
			}
		})
	}
}

// OSS kits record nothing for an unanswered pass and run no extra pass.
func TestB510KitOSSNoRecord(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeSkill(t, filepath.Join(home, ".claude/skills"), "slow", "x")
	cfg := testConfig("https://gw")
	var out bytes.Buffer
	post := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"x"},"tool_response":{},"cwd":"` + repo + `"}`
	RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Home: home, Stdin: strings.NewReader(post),
		Stdout: &out, Stderr: &out, Getenv: func(string) string { return "" },
		Send: func(context.Context, Request) (Response, string, error) {
			return Response{}, "", fmt.Errorf("%w: timeout", ErrUnreachable)
		}})
	if _, err := os.Stat(skillPendingPath(home)); !os.IsNotExist(err) {
		t.Fatalf("OSS kit wrote a pending record: %v", err)
	}
}
