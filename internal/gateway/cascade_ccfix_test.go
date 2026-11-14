// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A module that lowers every call it is asked about (S7 cascade review
// s7-ccrev, GAP-0579).
const cascadeAllowAllModule = `package defenseclaw.cascade
import rego.v1

decisions contains {"action": "allow", "id": "allow-all", "reason": "allow everything"} if { true }
`

// cascadeSurfaces are the surfaces whose verdict goes through the shared
// final step: the hook evaluators (Claude Code, Codex, the generic agent
// hook), /inspect/tool, the three content inspect endpoints and ACP.
var cascadeSurfaces = []struct{ connector, surface, event, tool string }{
	{"claudecode", "tool_call", "PreToolUse", "Bash"},
	{"codex", "tool_call", "PreToolUse", "shell"},
	{"cursor", "tool_call", "beforeShellExecution", "shell"},
	{"claudecode", "prompt", "UserPromptSubmit", ""},
	{"openclaw", "tool_call", "", "exec"},
	{"openclaw", "prompt", "", ""},
	{"openclaw", "response", "", ""},
	{"openclaw", "tool_result", "", ""},
	{"claudecode", "acp", "tool_call", ""},
}

// GAP-0579 probe matrix: policy.lowest {log, allow, alert} x {TRUNCATED,
// oversize-uninspected, normal} x every surface x {default, strict} pack,
// under a policy that lowers everything. An input DefenseClaw did not read
// in full ends at least at the unknown tier (default alert, strict block);
// a normal flagged call is lowered to the lowest limit as before.
func TestCascadeBoundFloorProbeMatrix(t *testing.T) {
	for _, posture := range []string{"default", "strict"} {
		tier, unknown := bounded.TierDefault, "alert"
		if posture == "strict" {
			tier, unknown = bounded.TierStrict, "block"
		}
		for _, lowest := range []string{"log", "allow", "alert"} {
			api := cascadeModuleConfig(t, posture, cascadeAllowAllModule, "")
			api.scannerCfg.Guardrail.Cascade.Policy.Lowest = lowest
			kinds := map[string]func() *ToolInspectVerdict{
				"truncated": func() *ToolInspectVerdict {
					v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
					v.floorBoundedTruncated(bounded.Of(bounded.Items), tier)
					return v
				},
				"truncated+finding": func() *ToolInspectVerdict {
					v := &ToolInspectVerdict{Action: "block", Severity: "HIGH", Findings: []string{"COG-CLAUDE-MD"},
						DetailedFindings: []RuleFinding{{RuleID: "COG-CLAUDE-MD", Severity: "HIGH"}}}
					v.floorBoundedTruncated(bounded.Of(bounded.Paths), tier)
					return v
				},
				"oversize-uninspected": func() *ToolInspectVerdict {
					v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
					v.markOversizeUninspected()
					return v
				},
				"normal": func() *ToolInspectVerdict {
					return &ToolInspectVerdict{Action: "block", Severity: "HIGH", Findings: []string{"COG-CLAUDE-MD"},
						DetailedFindings: []RuleFinding{{RuleID: "COG-CLAUDE-MD", Severity: "HIGH"}}}
				},
			}
			for kind, mk := range kinds {
				for _, s := range cascadeSurfaces {
					got := api.applyCascadeFinal(t.Context(), s.connector, s.surface, s.event, s.tool, mk())
					name := posture + "/" + lowest + "/" + kind + "/" + s.connector + "/" + s.surface
					if kind == "normal" {
						want := lowest
						if want == "log" {
							want = "allow"
						}
						if got.Action != want {
							t.Errorf("%s: a fully read flagged call ended %s, want the lowest limit %s", name, got.Action, want)
						}
						continue
					}
					if cascadeRank(got.Action) < cascadeRank(unknown) {
						t.Errorf("%s: FLOOR BROKEN: ended %s below the unknown tier %s (findings %v)", name, got.Action, unknown, got.Findings)
					}
				}
			}
		}
	}
}

// The same floor end to end on the Claude Code hook (a command over the
// operand cap), and on ACP through its own floor plus the shared step.
func TestCascadeBoundFloorHookEndToEnd(t *testing.T) {
	cmd := boundedListOperands(3000)
	for _, lowest := range []string{"", "alert", "log", "allow"} {
		api := cascadeModuleConfig(t, "default", cascadeAllowAllModule, "")
		api.scannerCfg.Guardrail.Cascade.Policy.Lowest = lowest
		ctx := withAuthenticatedHookConnector(t.Context(), "claudecode")
		got := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "ccfix", CWD: t.TempDir(), ToolName: "Bash",
			ToolInput: map[string]interface{}{"command": cmd},
		})
		if cascadeRank(got.Action) < cascadeRank("alert") && got.Action != "ask" {
			t.Errorf("lowest=%q: a truncated hook call ended %s", lowest, got.Action)
		}
	}
}

// The proxy (/llm, passthrough) keeps guardrail.rego and runs no cascade
// policy, so nothing there can lower a truncated input below the unknown
// tier whatever policy.lowest says.
func TestCascadeBoundFloorProxyPath(t *testing.T) {
	for _, lowest := range []string{"log", "allow", "alert"} {
		api := cascadeModuleConfig(t, "default", cascadeAllowAllModule, "")
		api.scannerCfg.Guardrail.Cascade.Policy.Lowest = lowest
		finding := boundedTruncatedFinding(bounded.Of(bounded.Bytes), true)
		for _, connector := range []string{"", "openclaw", "claudecode"} {
			got := guardrailActionForGuardrailFindings(&api.scannerCfg.Guardrail, connector, []RuleFinding{finding}, false)
			if cascadeRank(got) < cascadeRank("alert") {
				t.Errorf("lowest=%s connector=%q: proxy truncated input -> %s", lowest, connector, got)
			}
		}
	}
}

// GAP-0585: a decision the policy set is recorded with its input, and
// explain --last replays it to the same final action and rule.
func TestCascadeRecordedDecisionReplaysLive(t *testing.T) {
	api := cascadeModuleConfig(t, "default", cascadeAllowAllModule, "")
	api.scannerCfg.Guardrail.Cascade.Policy.Lowest = "allow"
	api.scannerCfg.DataDir = t.TempDir()
	live := api.applyCascadeFinal(t.Context(), "claudecode", "tool_call", "PreToolUse", "Bash", &ToolInspectVerdict{
		Action: "block", Severity: "HIGH", Findings: []string{"COG-CLAUDE-MD"},
		DetailedFindings: []RuleFinding{{RuleID: "COG-CLAUDE-MD", Severity: "HIGH"}},
	})
	if live.Action != "allow" {
		t.Fatalf("live = %s", live.Action)
	}
	flushCascadeRecords()
	rec, err := ReadCascadeDecision(api.scannerCfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Connector != "claudecode" || rec.Live.Final != "allow" || rec.Live.PolicyRule != "allow-all" || rec.Input == nil {
		t.Fatalf("record = %+v", rec)
	}
	sim, err := SimulateCascade(t.Context(), api.scannerCfg, rec.Connector, rec.Input)
	if err != nil {
		t.Fatal(err)
	}
	if sim.Outcome.Final != rec.Live.Final || sim.Outcome.PolicyRule != rec.Live.PolicyRule {
		t.Fatalf("replay %+v != live %+v", sim.Outcome, rec.Live)
	}
	info, err := os.Stat(filepath.Join(api.scannerCfg.DataDir, CascadeDecisionsFile))
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("record file %v %v", info, err)
	}
	if _, err := ReadCascadeDecision(api.scannerCfg, 2); err == nil {
		t.Fatal("a second record that was never written")
	}
}

// The record file stays bounded: a full file moves to .1.
func TestCascadeRecordRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), CascadeDecisionsFile)
	line := []byte(strings.Repeat("x", 4096) + "\n")
	for i := 0; i < (maxCascadeRecordBytes/len(line))+10; i++ {
		if err := appendCascadeRecord(path, line); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".1"} {
		info, err := os.Stat(p)
		if err != nil || info.Size() > maxCascadeRecordBytes {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
}

// GAP-0582: a reload whose top-level cascade is invalid is refused before
// anything is built; the live generation stays and the reason is the
// policy's last reload error. A narrower-scope lock violation is not a
// refusal (the gateway ignores that value and keeps the admin's cascade).
func TestCascadeInvalidReloadIsRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	load := func(body string) *config.Config {
		t.Helper()
		cfg, err := config.LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 9\ndata_dir: "+filepath.Join(home, "state")+"\n"+body))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	old := load("guardrail:\n  cascade:\n    unknown: block\n")
	bad := load("guardrail:\n  cascade:\n    unknown: allow\n")
	if bad.Guardrail.Cascade.Invalid() == nil {
		t.Fatal("candidate not invalid")
	}
	prevErr, _ := liveReloadError.Load().(string)
	t.Cleanup(func() { liveReloadError.Store(prevErr) })
	before := liveGeneration.Load()
	s := &Sidecar{}
	err := s.applyConfigReloadSnapshot(t.Context(), old, bad, ConfigDiff{}, configReloadSource{})
	if err == nil || !strings.Contains(err.Error(), "config reload refused: guardrail.cascade is invalid") {
		t.Fatalf("reload = %v", err)
	}
	if msg, _ := liveReloadError.Load().(string); !strings.Contains(msg, "guardrail.cascade") {
		t.Fatalf("last reload error = %q", msg)
	}
	if liveGeneration.Load() != before {
		t.Fatal("a refused reload changed the live generation")
	}
	locked := load("guardrail:\n  cascade:\n    unknown: block\n    admin:\n      locked: [block_at]\n  profiles:\n    p:\n      block_at: CRITICAL\n")
	if locked.Guardrail.Cascade.Invalid() != nil {
		t.Fatal("lock violation fell back")
	}
	if err := s.applyConfigReloadSnapshot(t.Context(), old, locked, ConfigDiff{}, configReloadSource{}); err != nil &&
		strings.Contains(err.Error(), "guardrail.cascade is invalid") {
		t.Fatalf("a narrower lock violation refused the reload: %v", err)
	}
}

// Ignored narrower values are reported once per message (stderr, an audit
// row) and in explain.
func TestCascadeIgnoredValuesAreReported(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	cfg, err := config.LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 9\ndata_dir: "+filepath.Join(home, "state")+
		"\nguardrail:\n  cascade:\n    unknown: block\n    admin:\n      locked: [unknown]\n  connectors:\n    codex:\n      cascade:\n        unknown: alert\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConfigFilePath = filepath.Join(home, "ccfix-ignored.yaml")
	t.Cleanup(func() { cascadeIgnoredReported.Delete(cfg.ConfigFilePath) })
	noteCascade(nil, &Generation{Config: cfg})
	if msg, ok := cascadeIgnoredReported.Load(cfg.ConfigFilePath); !ok || !strings.Contains(msg.(string), "guardrail.connectors.codex.cascade.unknown") {
		t.Fatalf("not reported: %v", msg)
	}
	ex, err := ExplainCascade(cfg, "codex", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Ignored) != 1 || ex.Ignored[0].Path != "guardrail.connectors.codex.cascade.unknown" || ex.Unknown.Setting != "block" {
		t.Fatalf("explain: %+v", ex)
	}
}

// GAP-0585 bench: the Rego final step at 100 calls/s (the hook-path target),
// p50/p99 per decision with the documented modules. Opt-in, since it takes
// DEFENSECLAW_CASCADE_BENCH seconds:
//
//	DEFENSECLAW_CASCADE_BENCH=20 go test -run TestCascadePolicyLatencyAt100PerSecond -v ./internal/gateway/
func TestCascadePolicyLatencyAt100PerSecond(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("DEFENSECLAW_CASCADE_BENCH"))
	if seconds <= 0 {
		t.Skip("set DEFENSECLAW_CASCADE_BENCH=<seconds> to run the Rego latency bench")
	}
	modules := map[string]string{"allow-all": cascadeAllowAllModule, "test-module": cascadeTestModule, "docs-secrets": cascadeDocsSecretsModule}
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		api := cascadeModuleConfig(t, "default", modules[name], "")
		verdict := func(i int) *ToolInspectVerdict {
			findings := []RuleFinding{{RuleID: "SEC-AWS-KEY", Severity: "MEDIUM"}, {RuleID: "COG-CLAUDE-MD", Severity: "HIGH"},
				{RuleID: "SHELL-EXFIL", Severity: "HIGH", Tags: []string{"exfil", "network"}}}
			return &ToolInspectVerdict{Action: "block", Severity: "HIGH", Findings: []string{"SEC-AWS-KEY", "COG-CLAUDE-MD", "SHELL-EXFIL"},
				DetailedFindings: findings[:1+i%3]}
		}
		var mu sync.Mutex
		var lat []time.Duration
		var errs int
		var wg sync.WaitGroup
		ticker := time.NewTicker(10 * time.Millisecond)
		deadline := time.Now().Add(time.Duration(seconds) * time.Second)
		for i := 0; time.Now().Before(deadline); i++ {
			<-ticker.C
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				start := time.Now()
				v := api.applyCascadeFinal(context.Background(), "claudecode", "tool_call", "PreToolUse", "Bash", verdict(i))
				d := time.Since(start)
				mu.Lock()
				lat = append(lat, d)
				if slices.Contains(v.Findings, cascadePolicyErrorID) {
					errs++
				}
				mu.Unlock()
			}(i)
		}
		ticker.Stop()
		wg.Wait()
		slices.Sort(lat)
		pct := func(p float64) time.Duration { return lat[min(len(lat)-1, int(float64(len(lat))*p))] }
		t.Logf("CASCADE-REGO-BENCH module=%s rate=100/s decisions=%d p50=%s p99=%s max=%s policy_errors=%d budget=%s",
			name, len(lat), pct(0.50), pct(0.99), lat[len(lat)-1], errs, config.DefaultCascadePolicyTimeout)
		// A decision over the budget is judged as unknown (never allow); the
		// bench fails only when the typical (p99) decision misses it.
		if pct(0.99) > config.DefaultCascadePolicyTimeout {
			t.Errorf("%s: p99 %s is over the %s policy budget at 100 calls/s (%d of %d decisions went to the unknown tier)",
				name, pct(0.99), config.DefaultCascadePolicyTimeout, errs, len(lat))
		}
	}
}

// The docs example module (guardrail/configure-cascade: secrets block at
// MEDIUM).
const cascadeDocsSecretsModule = `package defenseclaw.cascade
import rego.v1

decisions contains {"action": "block", "id": "secrets-medium", "reason": "secrets block at MEDIUM and above"} if {
	some f in input.findings
	f.enforceable
	startswith(f.rule_id, "SEC-")
	f.severity in {"MEDIUM", "HIGH", "CRITICAL"}
}
`
