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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
// oversize-uninspected, the 256 KiB content cut, each from allow, alert and
// a proven block, normal} x every surface x {default, strict} pack, under a
// policy that lowers everything. An input DefenseClaw did not read in full
// ends at least at the unknown tier (default alert, strict block), and a
// block the read part proved stays a block (s7-ccrev2's 54-cell probe is
// the oversize+block rows); a normal flagged call is lowered to the lowest
// limit as before.
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
				"oversize+block": func() *ToolInspectVerdict {
					v := ruleVerdict("block", "HIGH")
					v.markOversizeUninspected()
					return v
				},
				"oversize+alert": func() *ToolInspectVerdict {
					v := ruleVerdict("alert", "MEDIUM")
					v.markOversizeUninspected()
					return v
				},
				"cut": func() *ToolInspectVerdict {
					v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
					v.markContentCut(unknown)
					return v
				},
				"cut+alert": func() *ToolInspectVerdict {
					v := ruleVerdict("alert", "MEDIUM")
					v.markContentCut(unknown)
					return v
				},
				"cut+block": func() *ToolInspectVerdict {
					v := ruleVerdict("block", "HIGH")
					v.markContentCut(unknown)
					return v
				},
				"normal": func() *ToolInspectVerdict {
					return ruleVerdict("block", "HIGH")
				},
			}
			provenBlock := map[string]bool{"truncated+finding": true, "oversize+block": true, "cut+block": true}
			for kind, mk := range kinds {
				for _, s := range cascadeSurfaces {
					got := api.applyCascadeFinal(t.Context(), s.connector, s.surface, s.event, s.tool, mk())
					name := posture + "/" + lowest + "/" + kind + "/" + s.connector + "/" + s.surface
					if provenBlock[kind] && got.Action != "block" {
						t.Errorf("%s: a block proven before the cap ended %s (findings %v, reason %q)", name, got.Action, got.Findings, got.Reason)
					}
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

func ruleVerdict(action, severity string) *ToolInspectVerdict {
	return &ToolInspectVerdict{Action: action, Severity: severity, Findings: []string{"COG-CLAUDE-MD"},
		DetailedFindings: []RuleFinding{{RuleID: "COG-CLAUDE-MD", Severity: severity}}}
}

// The marker is set whatever the verdict (GAP-0579): a block the bounded
// prefix proved keeps its reason and gains the marker; the 256 KiB cut
// raises to the unknown tier and never lowers.
func TestCascadeUninspectedMarkerWhateverTheVerdict(t *testing.T) {
	v := ruleVerdict("block", "HIGH")
	v.markOversizeUninspected()
	v.markOversizeUninspected()
	if !cascadeUninspected(v) || !cascadeInputProvenBlockOf(v, false) || v.Findings[0] != hookOversizeUninspectedRuleID || len(v.Findings) != 2 {
		t.Fatalf("oversize after a block: uninspected=%v proven=%v findings=%v", cascadeUninspected(v), cascadeInputProvenBlockOf(v, false), v.Findings)
	}
	v = &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
	v.markOversizeUninspected()
	if v.Action != "block" || cascadeInputProvenBlockOf(v, false) {
		t.Fatalf("oversize from allow: action=%s proven=%v", v.Action, cascadeInputProvenBlockOf(v, false))
	}
	for unknown, want := range map[string]string{"alert": "alert", "confirm": "alert", "block": "block", "": "alert"} {
		v = &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
		v.markContentCut(unknown)
		if v.Action != want || !cascadeUninspected(v) || cascadeInputProvenBlockOf(v, false) || v.Reason != contentCutReason {
			t.Errorf("cut from allow, unknown %q: action=%s (want %s) uninspected=%v reason=%q", unknown, v.Action, want, cascadeUninspected(v), v.Reason)
		}
	}
	v = ruleVerdict("block", "HIGH")
	v.markContentCut("alert")
	if v.Action != "block" || !cascadeInputProvenBlockOf(v, false) {
		t.Fatalf("cut after a block: action=%s proven=%v", v.Action, cascadeInputProvenBlockOf(v, false))
	}
}

// The 256 KiB cut on the inspect routes marks the call: a benign prompt
// over the cap is at least the unknown tier, never a silent allow, and a
// policy that lowers everything cannot take it below that.
func TestCascadeInspectContentCutIsUninspected(t *testing.T) {
	// The verdict on a cut, not the scan latency, is under test. Under
	// -race with coverage on a 4-vCPU CI runner, the first scan of the
	// 256 KiB kept prefix (with the rule generation the handlers compile on
	// first use, which a booted gateway compiled already) can pass the
	// 200 ms production deadline (inspectScanTimeout), and the route then
	// answers 504 with no verdict (rel-1-0-10:GAP-0958, CI #1457 shard 23).
	// TestInspectContentRoutesAnswer504PastTheScanBudget covers the deadline.
	api := cascadeModuleConfig(t, "default", cascadeAllowAllModule, "")
	api.inspectToolScanTimeout = 30 * time.Second
	api.scannerCfg.Guardrail.Cascade.Policy.Lowest = "allow"
	api.scannerCfg.Guardrail.Mode = "action"
	big := strings.Repeat("hello world ", maxInspectContentLen/12+64)
	for _, tc := range []struct {
		path string
		h    http.HandlerFunc
		body any
	}{
		{"/api/v1/inspect/request", api.handleInspectRequest, RequestInspectRequest{Content: big}},
		{"/api/v1/inspect/response", api.handleInspectResponse, ResponseInspectRequest{Content: big}},
	} {
		raw, _ := json.Marshal(tc.body)
		rec := httptest.NewRecorder()
		tc.h(rec, httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(raw)))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", tc.path, rec.Code, rec.Body.String())
		}
		var got ToolInspectVerdict
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %v (%d %s)", tc.path, err, rec.Code, rec.Body.String())
		}
		if cascadeRank(got.Action) < cascadeRank("alert") || !slices.Contains(got.Findings, hookOversizeUninspectedRuleID) {
			t.Errorf("%s: content over the cap ended %s findings %v", tc.path, got.Action, got.Findings)
		}
	}
}

// The content inspect routes keep the 200 ms production scan deadline
// unless a test widens it, and past the deadline they answer 504 with no
// verdict, which the callers handle by their fail mode (GAP-0958). The
// budget is pinned on the server the gateway serves (NewAPIServer), and the
// tool-response route reads the same seam (rel-1-0-10:GAP-1036).
func TestInspectContentRoutesAnswer504PastTheScanBudget(t *testing.T) {
	if got := (&APIServer{}).inspectScanBudget(); got != 200*time.Millisecond {
		t.Fatalf("production inspect scan budget = %s, want 200ms", got)
	}
	store, logger := testStoreAndLogger(t)
	served := &config.Config{}
	served.Guardrail.Mode = "action"
	if got := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, served).inspectScanBudget(); got != 200*time.Millisecond {
		t.Fatalf("NewAPIServer inspect scan budget = %s, want 200ms", got)
	}
	api := cascadeModuleConfig(t, "default", cascadeAllowAllModule, "")
	api.inspectToolScanTimeout = time.Nanosecond
	big := strings.Repeat("hello world ", maxInspectContentLen/12)
	for _, tc := range []struct {
		path string
		h    http.HandlerFunc
		body any
	}{
		{"/api/v1/inspect/request", api.handleInspectRequest, RequestInspectRequest{Content: big}},
		{"/api/v1/inspect/response", api.handleInspectResponse, ResponseInspectRequest{Content: big}},
		{"/api/v1/inspect/tool-response", api.handleInspectToolResponse, ToolResponseInspectRequest{Tool: "Bash", Output: mustJSON(t, big)}},
	} {
		raw, _ := json.Marshal(tc.body)
		rec := httptest.NewRecorder()
		tc.h(rec, httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(raw)))
		if rec.Code != http.StatusGatewayTimeout || !strings.Contains(rec.Body.String(), "scan timeout") {
			t.Errorf("%s past the scan budget: status %d %s, want 504 scan timeout", tc.path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `"action"`) {
			t.Errorf("%s past the scan budget answered a verdict: %s", tc.path, rec.Body.String())
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
	// The per-user data dir is private (0700; on Windows a protected
	// owner-only DACL the record inherits), not a shared temp tree.
	api.scannerCfg.DataDir = testenv.PrivateTempDir(t)
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
	// Owner-only: mode 0600 on POSIX, the inherited DACL on Windows.
	assertCascadeRecordPrivate(t, filepath.Join(api.scannerCfg.DataDir, CascadeDecisionsFile))
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

// GAP-0580: cascade explain shows the mode that applies, the locked
// top-level one, for a connector under application_protection, with and
// without a profile.
func TestCascadeExplainLockedModeUnderApplicationProtection(t *testing.T) {
	raw := []byte("config_version: 9\ndata_dir: " + t.TempDir() + "\n" +
		"guardrail:\n  enabled: true\n  mode: action\n  cascade:\n    admin:\n      locked: [mode]\n" +
		"  profiles:\n    contractors:\n      mode: observe\n" +
		"application_protection:\n  enabled: true\n  guardrail:\n    mode: observe\n")
	t.Setenv("HOME", t.TempDir())
	cfg, err := config.LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"", "contractors"} {
		for _, c := range []string{"cursor", "codex"} {
			ex, err := ExplainCascade(cfg, c, profile)
			if err != nil {
				t.Fatal(err)
			}
			if ex.Rules.Mode != "action" {
				t.Errorf("profile %q, %s: explain shows mode %s, want the locked action", profile, c, ex.Rules.Mode)
			}
		}
	}
}
