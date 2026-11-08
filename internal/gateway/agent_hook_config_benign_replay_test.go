// D1 benign replay for gx048 round 4.
// Only calls that pass the guard's own entry conditions are judged; every
// other call cannot reach the gx048 rules.

package gateway

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rv3D1Judge keeps the same handler and audit store across the corpus. A
// fresh store per cell consumes memory proportional to the number of calls
// and makes the replay much slower than the guard it measures.
func rv3D1Judge(t *testing.T, profile, cwd string) func(string, map[string]any) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	if profile == "strict" {
		installToolCallCorpusProfileConnector(t, "claudecode", "strict")
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	handler := api.handleAgentHook("claudecode")
	return func(tool string, input map[string]any) string {
		payload := mustJSON(t, map[string]any{
			"session_id": "rv3gx048", "hook_event_name": "PreToolUse",
			"tool_name": tool, "cwd": cwd, "tool_input": input,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
}

func TestRV3GX048D1(t *testing.T) {
	shellPath, filesPath := os.Getenv("RV3_D1_SHELL"), os.Getenv("RV3_D1_FILES")
	if shellPath == "" || filesPath == "" {
		t.Skip("no corpus")
	}
	h := newGAP0048Home(t)
	homeRe := regexp.MustCompile(`(/Users/[^/\\"' ]+|/home/[^/\\"' ]+|[A-Za-z]:\\\\Users\\\\[^\\"' ]+)`)
	guard := newAgentHookConfigGuard(h.project, h.home)
	judges := map[string]func(string, map[string]any) string{
		"default": rv3D1Judge(t, "default", h.project),
		"strict":  rv3D1Judge(t, "strict", h.project),
	}
	agents := []string{"git ", "claude ", "codex ", "opencode ", "amp ", "copilot ", "kiro-cli ", "hermes ", "cursor-agent ", "devin ", "gemini ", "npx "}
	reach := func(text string) bool {
		lower := strings.ToLower(text)
		if guard.shellMentionsRegistryPath(lower) {
			return true
		}
		for _, a := range agents {
			if strings.Contains(lower, a) {
				return true
			}
		}
		return false
	}
	total, judged, strictGitBlocks := 0, 0, 0
	tally := map[string]int{}
	run := func(id, tool string, in map[string]any) {
		judged++
		for _, profile := range []string{"default", "strict"} {
			got := judges[profile](tool, in)
			rule := "-"
			if strings.Contains(got, agentHookConfigDisableRuleID) {
				rule = "disable"
			} else if strings.Contains(got, agentHookConfigWriteRuleID) {
				rule = "write"
			}
			action := rv2Action(got)
			tally[profile+"/"+action+"/"+rule]++
			if profile == "strict" && action == "block" && rule != "-" {
				if command, _ := in["command"].(string); strings.Contains(command, "git ") {
					strictGitBlocks++
				}
			}
			if rule != "-" {
				text, _ := json.Marshal(in)
				s := string(text)
				if len(s) > 160 {
					s = s[:160]
				}
				t.Logf("RV3D1|%s|%s|%s|%s|%s", id, profile, action, rule, s)
			}
		}
	}
	scan := func(path string, each func(map[string]any)) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var row map[string]any
			if json.Unmarshal(sc.Bytes(), &row) == nil {
				each(row)
			}
		}
	}
	scan(shellPath, func(row map[string]any) {
		total++
		cmd, _ := row["command"].(string)
		if cmd == "" || row["tool_name"] == "PowerShell" {
			return
		}
		cmd = homeRe.ReplaceAllString(cmd, h.home)
		if !reach(cmd) {
			return
		}
		id, _ := row["id"].(string)
		run(id, "Bash", map[string]any{"command": cmd})
	})
	scan(filesPath, func(row map[string]any) {
		total++
		tool, _ := row["cc_tool"].(string)
		args, ok := row["args"].(map[string]any)
		if tool == "" || !ok {
			return
		}
		raw, _ := json.Marshal(args)
		text := homeRe.ReplaceAllString(string(raw), strings.ReplaceAll(h.home, `\`, `\\`))
		if !reach(text) {
			return
		}
		var in map[string]any
		if json.Unmarshal([]byte(text), &in) != nil {
			return
		}
		id, _ := row["id"].(string)
		run(id, tool, in)
	})
	t.Logf("RV3D1TALLY total=%d judged=%d %v", total, judged, tally)
	if tally["default/block/disable"] != 0 || tally["default/block/write"] != 0 {
		t.Fatalf("balanced blocked benign gx048 calls: %v", tally)
	}
	if strictGitBlocks != 0 {
		t.Fatalf("strict blocked %d benign git calls", strictGitBlocks)
	}
}
