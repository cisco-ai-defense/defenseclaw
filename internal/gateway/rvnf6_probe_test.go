//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestRVNF6Probe(t *testing.T) {
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	installDefaultProfileConnector(t, "claudecode")
	if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	os.MkdirAll(filepath.Join(home, ".claude"), 0700)
	base := gap0433LaptopSettings
	with := func(m string) string { return "{" + m + "," + base[1:] }
	verdict := func(fs []RuleFinding) string {
		if len(fs) == 0 {
			return "allow/NONE"
		}
		var out []string
		for _, f := range fs {
			k := "alert"
			if f.RuleID == agentHookConfigDisableRuleID {
				k = "block"
			}
			out = append(out, k+"/"+f.Severity+"/"+f.RuleID+"("+f.Title+")")
		}
		return strings.Join(out, ";")
	}
	type row struct {
		name, file, tool string
		input            map[string]any
		facts            string // "exact", "none", "missing"
	}
	S := "{H}/.claude/settings.json"
	rows := []row{
		{"A benign multiedit transient invalid", with(`"model":"zzz"`), "MultiEdit", map[string]any{"file_path": S, "edits": []any{
			map[string]any{"old_string": `"model":"zzz"`, "new_string": `"model":"zzz","alwaysThinkingEnabled":`},
			map[string]any{"old_string": `"alwaysThinkingEnabled":,`, "new_string": `"alwaysThinkingEnabled":true,`}}}, "exact"},
		{"A2 benign multiedit move hooks", with(`"model":"zzz"`), "MultiEdit", map[string]any{"file_path": S, "edits": []any{
			map[string]any{"old_string": `"model":"zzz",`, "new_string": ``},
			map[string]any{"old_string": `}}`, "new_string": `},"model":"zzz"}`}}}, "exact"},
		{"C empty file edit create", "", "Edit", map[string]any{"file_path": S, "old_string": "", "new_string": `{"model":"x"}`}, "exact"},
		{"D broken file repaired", `{"model":"x",}`, "Edit", map[string]any{"file_path": S, "old_string": `"x",}`, "new_string": `"x"}`}, "exact"},
		{"D2 broken file Write", `{"model":"x",}`, "Write", map[string]any{"file_path": S, "content": `{"model":"x"}`}, "exact"},
		{"E fallback C20 LD", with(`"env":{"LD_LIBRARY_PATH":"/opt/lib"}`), "Edit", map[string]any{"file_path": S, "old_string": `"/opt/lib"`, "new_string": `"/tmp/evil"`}, "none"},
		{"E2 fallback NODE split", with(`"env":{"NODE_OPTIONS":"--max-old-space-size=4096"}`), "Edit", map[string]any{"file_path": S, "old_string": "max-old-space-size=4096", "new_string": "require=/tmp/x.js"}, "none"},
		{"E3 fallback switch space", with(`"disableAllHooks": false`), "Edit", map[string]any{"file_path": S, "old_string": " false", "new_string": " true"}, "none"},
		{"F fallback benign model", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": S, "old_string": `"zzz"`, "new_string": `"yyy"`}, "none"},
		{"G missing file edit create", "", "Edit", map[string]any{"file_path": S, "old_string": "", "new_string": `{"model":"x"}`}, "missing"},
		{"H tilde path exact", with(`"env":{"LD_LIBRARY_PATH":"/opt/lib"}`), "Edit", map[string]any{"file_path": "~/.claude/settings.json", "old_string": `"/opt/lib"`, "new_string": `"/tmp/evil"`}, "exact"},
	}
	for _, r := range rows {
		p := filepath.Join(home, ".claude", "settings.json")
		os.Remove(p)
		if r.facts != "missing" {
			os.WriteFile(p, []byte(r.file), 0600)
		}
		input := gap0264Expand(r.input, home, home).(map[string]any)
		args, _ := json.Marshal(input)
		req := trustedActionRequest{Connector: "claudecode", EnforcementCapable: true, Input: actionfacts.Input{Tool: r.tool, Args: args, ActiveHome: home, CWD: home}}
		laptop := agentHookConfigFindingsAs(context.Background(), req, nil)
		ai := gap0264Expand(r.input, gap0264ActorWorkdir, sandboxauth.SandboxHome).(map[string]any)
		req.Input.Args, _ = json.Marshal(ai)
		req.Input.ActiveHome = sandboxauth.SandboxHome
		req.Input.CWD = gap0264ActorWorkdir
		for _, withFacts := range []bool{true, false} {
			ctx := context.Background()
			if withFacts {
				ctx = gapNF6Facts(ctx, r.file)
			}
			actor := sandboxAgentHookConfigFindings(ctx, req, nil)
			t.Logf("RVNF6 %-40s facts=%t laptop=%s || actor=%s", r.name, withFacts, verdict(laptop), verdict(actor))
			gapNF6Probe(t, fmt.Sprintf("RVNF6 %s/facts=%t", r.name, withFacts), r.file, r.input, verdict(laptop), verdict(actor))
			expected := verdictClassNF7(laptop)
			// No-copy scalar/member fragments cannot prove their key context.
			// Broken-file Write is also ambiguous without its original bytes.
			// An Edit that creates the file has a known before-state (empty)
			// and gets the laptop verdict (substrate-1 GAP-0617).
			if !withFacts && r.input["old_string"] != "" {
				expected = agentHookConfigDisableRuleID + "/CRITICAL"
			}
			if verdictClassNF7(actor) != expected {
				t.Errorf("%s facts=%t laptop=%s actor=%s, want %s", r.name, withFacts, verdict(laptop), verdict(actor), expected)
			}
		}
	}
}

// Compare action/severity/rule independently of explanatory titles.
func verdictClassNF7(fs []RuleFinding) string {
	if len(fs) == 0 {
		return "allow/NONE"
	}
	return fs[0].RuleID + "/" + fs[0].Severity
}
