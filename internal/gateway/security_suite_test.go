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

// Security + PII coverage suite.
//
// The suite is split into three tiers so it is always explicit WHICH layer
// is under test:
//
//   - TestSecuritySuiteRegex  — the deterministic regex/rule layer
//     (ScanAllRules + GuardrailInspector in regex_only mode). No LLM.
//   - TestSecuritySuiteJudge  — the LLM-judge layer. Deterministic by
//     default via a scripted mock provider; scores against a live judge
//     when GUARDRAIL_BENCHMARK_LLM=1.
//   - TestSecuritySuiteE2E    — the HTTP inspect API on a running gateway.
//     Skipped unless DEFENSECLAW_GATEWAY_URL is set.
//
// Each corpus row asserts a correct expected outcome (severity floor for
// attacks, severity ceiling for benign false-positive guards). Adding a
// case is data-only: append a line to the relevant corpus.jsonl.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// ---------------------------------------------------------------------------
// Shared schema + assertions
// ---------------------------------------------------------------------------

// expectation is the common pass/fail contract shared by all three tiers.
type expectation struct {
	ExpectedSeverityAtLeast  string   `json:"expected_severity_at_least,omitempty"`
	ForbiddenSeverityAtLeast string   `json:"forbidden_severity_at_least,omitempty"`
	MustIncludeFindingsSub   []string `json:"must_include_findings_substr,omitempty"`
}

// assertExpectation checks a (severity, findings) outcome against the
// case contract. Severity comparisons use severityRank so they are
// independent of action/profile/threshold mapping.
func assertExpectation(t *testing.T, exp expectation, sev string, findings []string) {
	t.Helper()
	got := severityRank[strings.ToUpper(strings.TrimSpace(sev))]

	if exp.ExpectedSeverityAtLeast != "" {
		want := severityRank[exp.ExpectedSeverityAtLeast]
		if got < want {
			t.Errorf("severity=%s, want >= %s (findings=%v)", sev, exp.ExpectedSeverityAtLeast, findings)
		}
	}
	if exp.ForbiddenSeverityAtLeast != "" {
		forbidden := severityRank[exp.ForbiddenSeverityAtLeast]
		if got >= forbidden {
			t.Errorf("severity=%s is >= forbidden %s (findings=%v)", sev, exp.ForbiddenSeverityAtLeast, findings)
		}
	}
	if len(exp.MustIncludeFindingsSub) > 0 {
		combined := strings.Join(findings, ",")
		for _, sub := range exp.MustIncludeFindingsSub {
			if !strings.Contains(combined, sub) {
				t.Errorf("findings missing substring %q; got %v", sub, findings)
			}
		}
	}
}

// readJSONL reads a corpus.jsonl file and unmarshals each non-empty,
// non-comment line into a freshly allocated T.
func readJSONL[T any](t *testing.T, parts ...string) []T {
	t.Helper()
	path := filepath.Join(append([]string{"testdata", "security_suite"}, parts...)...)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			t.Fatalf("parse %s: %v\nline: %s", path, err, line)
		}
		out = append(out, item)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func ruleFindingStrings(findings []RuleFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID+":"+f.Title)
	}
	return out
}

// ---------------------------------------------------------------------------
// Tier 1: regex / rule layer (deterministic, no LLM)
// ---------------------------------------------------------------------------

type regexCase struct {
	ID        string `json:"id"`
	Direction string `json:"direction"`
	ToolName  string `json:"tool_name,omitempty"`
	Content   string `json:"content"`
	IsAttack  bool   `json:"is_attack"`
	// Surfaces selects which regex-layer entry points to replay against:
	// "scan_all_rules" (rule engine shared by hook + inspect API) and
	// "inspector" (GuardrailInspector regex_only, shared by proxy + sidecar).
	Surfaces []string `json:"surfaces"`
	expectation
}

// TestSecuritySuiteRegex replays the regex corpus through the deterministic
// rule layer. It exercises the same ScanAllRules engine the connector hook
// and /inspect API use, plus the GuardrailInspector regex_only path the
// proxy and sidecar share — so a regression shows up regardless of surface.
func TestSecuritySuiteRegex(t *testing.T) {
	// One corpus: curated hand-authored cases above the generated marker,
	// eval-derived cases below it (see TestGenerateRegexImportFromEvalCorpus).
	cases := readJSONL[regexCase](t, "regex", "corpus.jsonl")
	if len(cases) == 0 {
		t.Fatal("regex corpus empty")
	}

	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if len(c.Surfaces) == 0 {
				t.Fatalf("case %s has no surfaces", c.ID)
			}
			for _, surface := range c.Surfaces {
				surface := surface
				t.Run(surface, func(t *testing.T) {
					var sev string
					var findings []string
					switch surface {
					case "scan_all_rules":
						rf := ScanAllRules(c.Content, c.ToolName)
						sev, findings = HighestSeverity(rf), ruleFindingStrings(rf)
					case "inspector":
						g := NewGuardrailInspector("local", nil, nil, "")
						g.SetDetectionStrategy("regex_only", "", "", "", false)
						v := g.Inspect(context.Background(), c.Direction, c.Content, nil, "model", "observe")
						if v == nil {
							t.Fatal("inspector returned nil verdict")
						}
						sev, findings = v.Severity, v.Findings
					default:
						t.Fatalf("unknown regex surface %q", surface)
					}
					assertExpectation(t, c.expectation, sev, findings)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tier 2: LLM-judge layer (deterministic stub by default; live on opt-in)
// ---------------------------------------------------------------------------

type judgeCase struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"` // pii | injection | exfil | tool_injection
	Direction string          `json:"direction"`
	ToolName  string          `json:"tool_name,omitempty"`
	Content   string          `json:"content"`
	IsAttack  bool            `json:"is_attack"`
	Response  json.RawMessage `json:"response"` // scripted judge JSON for the deterministic tier
	expectation
}

func judgeConfigForKind(kind string) *config.JudgeConfig {
	cfg := &config.JudgeConfig{Enabled: true, Timeout: 5, AdjudicationTimeout: 5}
	switch kind {
	case "pii":
		cfg.PII, cfg.PIIPrompt, cfg.PIICompletion = true, true, true
	case "injection":
		cfg.Injection = true
	case "exfil":
		cfg.Exfil = true
	case "tool_injection":
		cfg.ToolInjection = true
	}
	return cfg
}

// stubJudge builds an LLMJudge backed by a scripted provider that returns
// the case's canned judge JSON. The judge code path (parsing, suppressions,
// severity mapping) runs for real — only the model answer is fixed.
func stubJudge(c judgeCase) *LLMJudge {
	prov := &mockLLMProvider{
		response: &ChatResponse{
			Choices: []ChatChoice{{Message: &ChatMessage{Content: string(c.Response)}}},
		},
	}
	return &LLMJudge{
		cfg:      judgeConfigForKind(c.Kind),
		provider: prov,
		rp:       guardrail.LoadRulePack(""),
	}
}

// liveJudge builds a real LLM-backed judge for the opt-in scoring tier.
func liveJudge(t *testing.T, kind string) *LLMJudge {
	t.Helper()
	cfg := judgeConfigForKind(kind)
	cfg.Timeout, cfg.AdjudicationTimeout = 60, 60
	model := os.Getenv("GUARDRAIL_BENCHMARK_MODEL")
	if model == "" {
		model = "us.anthropic.claude-sonnet-4-6"
	}
	llm := config.LLMConfig{Model: model, APIKeyEnv: "DEFENSECLAW_LLM_KEY"}
	j := NewLLMJudge(cfg, llm, "", guardrail.LoadRulePack(""), nil)
	if j == nil {
		t.Skipf("live judge %q failed to init; check DEFENSECLAW_LLM_KEY and model %q", kind, model)
	}
	return j
}

// TestSecuritySuiteJudge replays the judge corpus through the LLM-judge
// layer. Deterministic by default (scripted provider); set
// GUARDRAIL_BENCHMARK_LLM=1 (and DEFENSECLAW_LLM_KEY) to score the same
// corpus against a real model.
func TestSecuritySuiteJudge(t *testing.T) {
	cases := readJSONL[judgeCase](t, "judge", "corpus.jsonl")
	if len(cases) == 0 {
		t.Fatal("judge corpus empty")
	}
	live := os.Getenv("GUARDRAIL_BENCHMARK_LLM") == "1"

	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			var j *LLMJudge
			if live {
				j = liveJudge(t, c.Kind)
			} else {
				if len(c.Response) == 0 {
					t.Skip("no scripted response; set GUARDRAIL_BENCHMARK_LLM=1 to score live")
				}
				j = stubJudge(c)
			}

			var v *ScanVerdict
			if c.Kind == "tool_injection" {
				v = j.RunToolJudge(context.Background(), c.ToolName, c.Content)
			} else {
				v = j.RunJudges(context.Background(), c.Direction, c.Content, c.ToolName)
			}
			if v == nil {
				t.Fatal("judge returned nil verdict")
			}
			assertExpectation(t, c.expectation, v.Severity, v.Findings)
		})
	}
}

// ---------------------------------------------------------------------------
// Tier 3: end-to-end HTTP inspect API (live gateway, opt-in)
// ---------------------------------------------------------------------------

type e2eCase struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"` // request | response | tool-response
	Tool     string `json:"tool,omitempty"`
	Content  string `json:"content"`
	IsAttack bool   `json:"is_attack"`
	expectation
}

// TestSecuritySuiteE2E replays the e2e corpus against a running gateway's
// HTTP inspect API. Skipped unless DEFENSECLAW_GATEWAY_URL is set (e.g.
// http://127.0.0.1:18970). This is the only tier that exercises the real
// HTTP handlers + audit pipeline end to end.
func TestSecuritySuiteE2E(t *testing.T) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("DEFENSECLAW_GATEWAY_URL")), "/")
	if base == "" {
		t.Skip("e2e suite requires DEFENSECLAW_GATEWAY_URL (e.g. http://127.0.0.1:18970)")
	}
	cases := readJSONL[e2eCase](t, "e2e", "corpus.jsonl")
	if len(cases) == 0 {
		t.Fatal("e2e corpus empty")
	}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			var url string
			var body any
			switch c.Endpoint {
			case "request":
				url, body = base+"/api/v1/inspect/request", RequestInspectRequest{Content: c.Content}
			case "response":
				url, body = base+"/api/v1/inspect/response", ResponseInspectRequest{Content: c.Content}
			case "tool-response":
				url, body = base+"/api/v1/inspect/tool-response", ToolResponseInspectRequest{
					Tool:   c.Tool,
					Output: json.RawMessage(strconvQuote(c.Content)),
				}
			default:
				t.Fatalf("unknown e2e endpoint %q", c.Endpoint)
			}

			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v", url, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("POST %s: status %d", url, resp.StatusCode)
			}

			var verdict struct {
				Action   string   `json:"action"`
				Severity string   `json:"severity"`
				Findings []string `json:"findings"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&verdict); err != nil {
				t.Fatalf("decode verdict: %v", err)
			}
			assertExpectation(t, c.expectation, verdict.Severity, verdict.Findings)
		})
	}
}

// strconvQuote JSON-encodes a string into a quoted JSON string literal,
// used to wrap raw tool output as a JSON value for the tool-response body.
func strconvQuote(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}
