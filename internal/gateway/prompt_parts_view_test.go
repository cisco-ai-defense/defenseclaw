// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10:GAP-0465: the model reads the text parts of a message as one
// text, so the prompt rules read it that way too. The literals are rows of the
// regex corpus (testdata/security_suite/regex/corpus.jsonl), pinned by row id
// and rule id; a split point is searched, never written out, and no message
// prints the text.

var partJoinCases = []struct{ row, rule string }{
	{"injection/polite-ignore-previous-instructions", "TRUST-IGNORE-PREVIOUS"},
	{"injection/override-previous-instructions", "TRUST-OVERRIDE-INSTRUCT"},
	{"injection/disable-guardrails", "TRUST-SAFETY-OVERRIDE"},
}

func partJoinRowText(t *testing.T, row string) string {
	t.Helper()
	for _, c := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		if c.ID == row {
			return c.Content
		}
	}
	t.Fatalf("regex corpus row %s not found", row)
	return ""
}

func partJoinRuleHits(text, rule string) bool {
	for _, finding := range scanContentRuleCategoryWithGeneration(snapshotRulePackGeneration(""), text, "", ruleContentScopeUntrusted, "") {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

// partJoinSplit splits text into n (2 or 3) parts whose line-feed join no
// longer holds rule, while their concatenation (text itself) does.
func partJoinSplit(t *testing.T, row, rule string, n int) []string {
	t.Helper()
	text := partJoinRowText(t, row)
	if !partJoinRuleHits(text, rule) {
		t.Fatalf("row %s: %s does not match the whole row", row, rule)
	}
	var cuts []int
	for i := 1; i < len(text); i++ {
		if utf8.RuneStart(text[i]) {
			cuts = append(cuts, i)
		}
	}
	for _, i := range cuts {
		if partJoinRuleHits(text[:i]+"\n"+text[i:], rule) {
			continue
		}
		if n == 2 {
			return []string{text[:i], text[i:]}
		}
		for _, j := range cuts {
			if j == i {
				continue
			}
			a, b := min(i, j), max(i, j)
			parts := []string{text[:a], text[a:b], text[b:]}
			if !partJoinRuleHits(strings.Join(parts, "\n"), rule) {
				return parts
			}
		}
	}
	t.Fatalf("row %s: no %d-part split hides %s from the line-feed join", row, n, rule)
	return nil
}

func newPartJoinInspector(t *testing.T, strategy string) *GuardrailInspector {
	t.Helper()
	previous := liveGeneration.Load()
	liveGeneration.Store(nil)
	t.Cleanup(func() { liveGeneration.Store(previous) })
	inspector := NewGuardrailInspector("local", nil, nil)
	inspector.SetDetectionStrategy(strategy, "", "", "", false)
	return inspector
}

func partJoinHasRule(findings []string, rule string) bool {
	return slices.ContainsFunc(findings, func(finding string) bool { return strings.HasPrefix(finding, rule+":") })
}

func partJoinBlocks(typ string, parts []string) []map[string]any {
	blocks := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		blocks = append(blocks, map[string]any{"type": typ, "text": part})
	}
	return blocks
}

func TestPromptPartsViewReadsPartsAsTheModelDoes(t *testing.T) {
	decode := func(raw string) []ChatMessage {
		t.Helper()
		var messages []ChatMessage
		if err := json.Unmarshal([]byte(raw), &messages); err != nil {
			t.Fatal(err)
		}
		return messages
	}
	for _, tc := range []struct {
		name, raw, content, view string
	}{
		{"two text parts", `[{"role":"user","content":[{"type":"text","text":"alp"},{"type":"text","text":"ha beta"}]}]`, "alp\nha beta", "alpha beta"},
		{"whitespace-only part between", `[{"role":"user","content":[{"type":"text","text":"alp"},{"type":"text","text":" "},{"type":"text","text":"ha"}]}]`, "alp\n \nha", "alp ha"},
		{"image between (Anthropic)", `[{"role":"user","content":[{"type":"text","text":"alp"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}},{"type":"text","text":"ha"}]}]`, "alp\nha", "alpha"},
		{"image between (Bedrock)", `[{"role":"user","content":[{"text":"alp"},{"image":{"format":"png","source":{"bytes":"AA=="}}},{"text":"ha"}]}]`, "alp\n\nha", "alpha"},
		{"Responses input_text", `[{"role":"user","content":[{"type":"input_text","text":"alp"},{"type":"input_image","image_url":"data:,"},{"type":"input_text","text":"ha"}]}]`, "alp\nha", "alpha"},
		{"one part has no seam", `[{"role":"user","content":[{"type":"text","text":"alpha"}]}]`, "alpha", ""},
		{"string content has no seam", `[{"role":"user","content":"alp\nha"}]`, "alp\nha", ""},
	} {
		messages := decode(tc.raw)
		if got := promptInspectText(messages); got != tc.content {
			t.Errorf("%s: inspected %q, want %q", tc.name, got, tc.content)
		}
		if got := promptPartsJoinedText(promptInspectText(messages), messages, nil); got != tc.view {
			t.Errorf("%s: parts view %q, want %q", tc.name, got, tc.view)
		}
		// The parts stay off the wire: the upstream body is the original blocks.
		var original []map[string]json.RawMessage
		_ = json.Unmarshal([]byte(tc.raw), &original)
		out, err := json.Marshal(messages[0])
		if err != nil || !bytes.Contains(out, original[0]["content"]) || bytes.Contains(out, []byte("textParts")) {
			t.Errorf("%s: marshal %s (err %v)", tc.name, out, err)
		}
	}

	// A history message never rewrites the current turn it is not part of, and
	// the longer text is replaced before a shorter one inside it.
	history := decode(`[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]},{"role":"assistant","content":"ok"},{"role":"user","content":[{"type":"text","text":"x a"},{"type":"text","text":"b y"}]}]`)
	if got := promptPartsJoinedText(promptInspectText(history), history, nil); got != "x ab y" {
		t.Errorf("history: parts view %q, want %q", got, "x ab y")
	}
	stale := decode(`[{"role":"user","content":[{"type":"text","text":"alp"},{"type":"text","text":"ha"}]}]`)
	stale[0].Content = "alp\nhb"
	if got := promptPartsJoinedText("alp\nhb", stale, nil); got != "" {
		t.Errorf("rewritten Content: parts view %q, want none", got)
	}
	if got := promptPartsJoinedText("alp\nha", nil, [][]string{{"alp", "ha"}}); got != "alpha" {
		t.Errorf("extra parts: %q", got)
	}

	for _, tc := range []struct{ content, view string }{
		{`[{"type":"text","text":"alp"},{"type":"text","text":"ha"}]`, "alpha"},
		{`[{"type":"text","text":"alp"},{"type":"image_url","image_url":{"url":"data:,"}},{"type":"text","text":" ha"}]`, "alp ha"},
		{`{"role":"user","content":[{"type":"text","text":"alp"},{"type":"text","text":"ha"}]}`, "alpha"},
		{`{"parts":[{"text":"alp"},{"inlineData":{"mimeType":"image/png","data":"AA=="}},{"text":"ha"}]}`, "alpha"},
		{`[{"type":"text","text":"alpha"}]`, ""},
		{`alp ha`, ""},
		{`["alp","ha"]`, ""},
	} {
		if got := jsonContentPartsJoinedText(tc.content); got != tc.view {
			t.Errorf("json content %s: view %q, want %q", tc.content, got, tc.view)
		}
	}
}

// The pre-call check of a messages request (handleChatCompletion), for each
// detection strategy with no judge: a literal split across 2 and 3 text parts
// is found by rule id; the same parts joined with a line feed in one string
// are not (the evasion on rel).
func TestPromptSplitLiteralFoundByRuleID(t *testing.T) {
	for _, strategy := range []string{"regex_only", "regex_judge", "judge_first"} {
		inspector := newPartJoinInspector(t, strategy)
		check := func(messages []ChatMessage) []string {
			raw := promptInspectText(messages)
			verdict := inspectPromptWithRawRecheck(context.Background(), inspector, promptInspectionText(raw), raw, messages, "model", "action")
			if verdict == nil {
				return nil
			}
			return verdict.Findings
		}
		for _, tc := range partJoinCases {
			for _, n := range []int{2, 3} {
				parts := partJoinSplit(t, tc.row, tc.rule, n)
				split := partJoinChatMessages(t, string(mustJSON(t, []map[string]any{
					{"role": "system", "content": "be brief"},
					{"role": "user", "content": partJoinBlocks("text", parts)},
				})))
				if !partJoinHasRule(check(split), tc.rule) {
					t.Errorf("%s %s %d parts: %s not found", strategy, tc.row, n, tc.rule)
				}
				joined := []ChatMessage{{Role: "user", Content: strings.Join(parts, "\n")}}
				if partJoinHasRule(check(joined), tc.rule) {
					t.Errorf("%s %s %d parts: control found %s in the line-feed join", strategy, tc.row, n, tc.rule)
				}
			}
		}
	}
}

func partJoinChatMessages(t *testing.T, raw string) []ChatMessage {
	t.Helper()
	var messages []ChatMessage
	if err := json.Unmarshal([]byte(raw), &messages); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	return messages
}

// partJoinPassthrough sends bodies through handlePassthrough to a counting
// upstream and reports whether each was forwarded (not blocked).
func partJoinPassthrough(t *testing.T, proxy *GuardrailProxy) func(path string, body map[string]any) bool {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := providerDomains
	providerDomains = append(append(providerDomains[:0:0], providerDomains...), providerDomainEntry{target.Hostname(), "anthropic"})
	t.Cleanup(func() { providerDomains = original })
	return func(path string, body map[string]any) bool {
		before := hits.Load()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(mustJSON(t, body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", upstream.URL)
		req.Header.Set("X-AI-Auth", "Bearer inert-test")
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, req)
		return hits.Load() > before
	}
}

// Every /llm provider shape that carries text parts, through the real
// handlers: a literal split across 2 and 3 parts is blocked as the whole row
// is; a whitespace-only part between two parts is decided as the model reads
// it (the parts concatenated), and an image between two parts is skipped as
// the model skips it. Ollama /api/chat and /api/generate carry one string per
// message or prompt, so they have no part seam.
func TestPromptSplitLiteralPerProviderShape(t *testing.T) {
	image := map[string]map[string]any{
		"anthropic":   {"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "AA=="}},
		"bedrock":     {"image": map[string]any{"format": "png", "source": map[string]any{"bytes": "AA=="}}},
		"input_text":  {"type": "input_image", "image_url": "data:,"},
		"gemini":      {"inlineData": map[string]any{"mimeType": "image/png", "data": "AA=="}},
		"gemini-sys":  {"inlineData": map[string]any{"mimeType": "image/png", "data": "AA=="}},
		"openai-chat": {"type": "image_url", "image_url": map[string]any{"url": "data:,"}},
	}
	type shape struct {
		name, path string
		body       func(blocks []map[string]any) map[string]any
		block      func(text string) map[string]any
		imageKey   string
	}
	typed := func(typ string) func(string) map[string]any {
		return func(text string) map[string]any { return map[string]any{"type": typ, "text": text} }
	}
	bare := func(text string) map[string]any { return map[string]any{"text": text} }
	shapes := []shape{
		{"anthropic", "/v1/messages", func(b []map[string]any) map[string]any {
			return map[string]any{"system": "be brief", "messages": []map[string]any{{"role": "user", "content": b}}}
		}, typed("text"), "anthropic"},
		{"bedrock", "/model/m/converse", func(b []map[string]any) map[string]any {
			return map[string]any{"messages": []map[string]any{{"role": "user", "content": b}}}
		}, bare, "bedrock"},
		{"responses", "/v1/responses", func(b []map[string]any) map[string]any {
			return map[string]any{"instructions": "be brief", "input": []map[string]any{{"type": "message", "role": "user", "content": b}}}
		}, typed("input_text"), "input_text"},
		{"gemini", "/v1beta/models/gemini-2.5-pro:generateContent", func(b []map[string]any) map[string]any {
			return map[string]any{"contents": []map[string]any{{"role": "user", "parts": b}}}
		}, bare, "gemini"},
		{"gemini systemInstruction", "/v1beta/models/gemini-2.5-pro:generateContent", func(b []map[string]any) map[string]any {
			return map[string]any{"systemInstruction": map[string]any{"parts": b}}
		}, bare, "gemini-sys"},
	}
	proxy := newTestProxy(t, &mockProvider{}, newPartJoinInspector(t, "regex_only"), "action")
	passthrough := partJoinPassthrough(t, proxy)
	chat := func(blocks []map[string]any) bool {
		rec := postChat(t, proxy, mustJSON(t, map[string]any{"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": blocks}}}))
		var resp ChatResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("openai-chat: decode: %v", err)
		}
		return resp.ID != "chatcmpl-blocked"
	}
	type route struct {
		name  string
		send  func(blocks []map[string]any) bool
		block func(string) map[string]any
		image map[string]any
	}
	routes := []route{{"openai-chat", chat, typed("text"), image["openai-chat"]}}
	for _, s := range shapes {
		s := s
		routes = append(routes, route{s.name, func(b []map[string]any) bool { return passthrough(s.path, s.body(b)) }, s.block, image[s.imageKey]})
	}
	for _, r := range routes {
		blocks := func(parts ...string) []map[string]any {
			out := make([]map[string]any, 0, len(parts))
			for _, part := range parts {
				out = append(out, r.block(part))
			}
			return out
		}
		for _, tc := range partJoinCases {
			whole := partJoinRowText(t, tc.row)
			if r.send(blocks(whole)) {
				t.Fatalf("%s %s: the whole row in one part is forwarded; the route does not block %s", r.name, tc.row, tc.rule)
			}
			for _, n := range []int{2, 3} {
				parts := partJoinSplit(t, tc.row, tc.rule, n)
				if r.send(blocks(parts...)) {
					t.Errorf("%s %s: %d parts forwarded, want blocked", r.name, tc.row, n)
				}
				if !r.send(blocks(strings.Join(parts, "\n"))) {
					t.Logf("%s %s: the line-feed join in one part is also blocked (another rule)", r.name, tc.row)
				}
			}
			parts := partJoinSplit(t, tc.row, tc.rule, 2)
			spaced := blocks(parts[0], " ", parts[1])
			if got, want := r.send(spaced), r.send(blocks(parts[0]+" "+parts[1])); got != want {
				t.Errorf("%s %s: whitespace part between: forwarded %v, want %v (as one part)", r.name, tc.row, got, want)
			}
			withImage := []map[string]any{r.block(parts[0]), r.image, r.block(parts[1])}
			if r.send(withImage) {
				t.Errorf("%s %s: image between the parts: forwarded, want blocked", r.name, tc.row)
			}
		}
	}
}

// The hook route: a prompt field that holds a block array (stringified as
// JSON by the hook normalizer) is read as its parts concatenated, through the
// real normalization and evaluation (Hermes pre_llm_call: the extra
// user_message envelope and a top-level prompt field).
func TestHookPromptSplitLiteralFoundByRuleID(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"})
	evaluate := func(payload map[string]interface{}) agentHookResponse {
		t.Helper()
		return api.evaluateAgentHook(t.Context(), normalizeAgentHookRequestWithProfile("hermes", payload, profile))
	}
	envelope := func(message any) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": "pre_llm_call", "tool_name": nil, "tool_input": nil, "session_id": "sess-partjoin",
			"extra": map[string]interface{}{"user_message": message, "conversation_history": []interface{}{}, "is_first_turn": true},
		}
	}
	promptField := func(message any) map[string]interface{} {
		return map[string]interface{}{"hook_event_name": "pre_llm_call", "session_id": "sess-partjoin", "prompt": message}
	}
	for _, tc := range partJoinCases {
		for _, n := range []int{2, 3} {
			parts := partJoinSplit(t, tc.row, tc.rule, n)
			for name, build := range map[string]func(any) map[string]interface{}{"user_message": envelope, "prompt": promptField} {
				if got := evaluate(build(partJoinBlocks("text", parts))); !slices.Contains(got.RuleIDs, tc.rule) {
					t.Errorf("%s %s %d parts: rules %v, want %s", name, tc.row, n, got.RuleIDs, tc.rule)
				}
				if got := evaluate(build(strings.Join(parts, "\n"))); slices.Contains(got.RuleIDs, tc.rule) {
					t.Errorf("%s %s %d parts: control (line-feed join) found %s", name, tc.row, n, tc.rule)
				}
			}
		}
	}
}

// The OpenClaw session-message scan reads a block-array message as its parts
// concatenated; the stream's raw block JSON alone hides the seam.
func TestSessionPromptSplitLiteralFoundByRuleID(t *testing.T) {
	newPartJoinInspector(t, "regex_only")
	for _, tc := range partJoinCases {
		for _, n := range []int{2, 3} {
			content := string(mustJSON(t, partJoinBlocks("text", partJoinSplit(t, tc.row, tc.rule, n))))
			if v := scanLocalPatternsWithActivation("prompt", content, snapshotRulePackGeneration(""), nil); v != nil && partJoinHasRule(v.Findings, tc.rule) {
				t.Errorf("%s %d parts: control (raw block JSON) found %s", tc.row, n, tc.rule)
			}
			if v := sessionPromptLocalVerdict(content, snapshotRulePackGeneration(""), nil); v == nil || !partJoinHasRule(v.Findings, tc.rule) {
				t.Errorf("%s %d parts: %s not found", tc.row, n, tc.rule)
			}
		}
	}
}

func TestUnionRuleFindingsKeepsOneFindingPerRule(t *testing.T) {
	base := []RuleFinding{{RuleID: "A", Evidence: "x"}, {RuleID: "B", Evidence: "y", profile: "p1"}}
	view := []RuleFinding{{RuleID: "A", Evidence: "x2"}, {RuleID: "B", Evidence: "y"}, {RuleID: "C"}}
	got := unionRuleFindings(base, view)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.profile+"/"+f.RuleID+"/"+f.Evidence)
	}
	if want := []string{"/A/x", "p1/B/y", "/B/y", "/C/"}; !slices.Equal(ids, want) {
		t.Fatalf("union = %v, want %v", ids, want)
	}
	v := unionLocalPatternVerdicts(
		&ScanVerdict{Action: "alert", Severity: "MEDIUM", Findings: []string{"A:a"}, Scanner: "local-pattern"},
		&ScanVerdict{Action: "block", Severity: "CRITICAL", Findings: []string{"A:a", "C:c"}, Scanner: "local-pattern"},
	)
	if v.Severity != "CRITICAL" || !slices.Equal(v.Findings, []string{"A:a", "C:c"}) || v.Action != guardrailFallbackActionForSeverity("CRITICAL") {
		t.Fatalf("local union = %+v", v)
	}
	// rel-1-0-10:GAP-0527: a view with no new finding name can still find the
	// same rule stronger. The verdict is the higher of the two; this used to
	// be pinned the other way.
	same := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Findings: []string{"A:a"}}
	raised := unionLocalPatternVerdicts(same, &ScanVerdict{Severity: "CRITICAL", Findings: []string{"A:a"}})
	if raised.Severity != "CRITICAL" || raised.Action != guardrailFallbackActionForSeverity("CRITICAL") || !slices.Equal(raised.Findings, []string{"A:a"}) {
		t.Fatalf("a stronger view with no new finding: %+v, want CRITICAL", raised)
	}
	if same.Severity != "MEDIUM" || same.Action != "alert" {
		t.Fatalf("the union changed its base: %+v", same)
	}
	if unionLocalPatternVerdicts(same, &ScanVerdict{Severity: "LOW", Findings: []string{"A:a"}}) != same {
		t.Fatal("a view that adds nothing and is no stronger must leave the verdict as it is")
	}
}

// rel-1-0-10:GAP-0527: two scans of one message keep, per rule and profile
// member, the stronger finding (strongerRuleFinding): enforceable over
// alert-only over detection-only, then severity, then confidence. Ties keep the
// first scan's finding.
func TestUnionRuleFindingsKeepsTheStrongerFinding(t *testing.T) {
	demoted := RuleFinding{RuleID: "D", Severity: "LOW", Confidence: 0.4, Evidence: "weak", enforcement: findingEnforcementDetectionOnly}
	full := RuleFinding{RuleID: "D", Severity: "CRITICAL", Confidence: 0.8, Evidence: "strong"}
	lowAlert := RuleFinding{RuleID: "D", Severity: "LOW", Evidence: "alert", enforcement: findingEnforcementAlertOnly}
	lowEnforce := RuleFinding{RuleID: "D", Severity: "LOW", Evidence: "enforce"}
	lowSure := RuleFinding{RuleID: "D", Severity: "LOW", Confidence: 0.9, Evidence: "sure"}
	otherProfile := RuleFinding{RuleID: "D", Severity: "CRITICAL", Evidence: "member", profile: "p2"}
	for _, tc := range []struct {
		name       string
		base, view []RuleFinding
		want       []string
	}{
		{"view stronger", []RuleFinding{demoted}, []RuleFinding{full}, []string{"/strong"}},
		{"base stronger", []RuleFinding{full}, []RuleFinding{demoted}, []string{"/strong"}},
		{"enforceable over detection-only", []RuleFinding{demoted}, []RuleFinding{lowEnforce}, []string{"/enforce"}},
		{"alert-only over detection-only", []RuleFinding{demoted}, []RuleFinding{lowAlert}, []string{"/alert"}},
		{"enforceable over alert-only", []RuleFinding{lowAlert}, []RuleFinding{lowEnforce}, []string{"/enforce"}},
		{"confidence last", []RuleFinding{lowEnforce}, []RuleFinding{lowSure}, []string{"/sure"}},
		{"tie keeps base", []RuleFinding{lowSure}, []RuleFinding{lowSure, lowEnforce}, []string{"/sure"}},
		{"profile members apart", []RuleFinding{demoted}, []RuleFinding{otherProfile}, []string{"/weak", "p2/member"}},
	} {
		base := slices.Clone(tc.base)
		var got []string
		for _, f := range unionRuleFindings(base, tc.view) {
			got = append(got, f.profile+"/"+f.Evidence)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: union = %v, want %v", tc.name, got, tc.want)
		}
		if !slices.EqualFunc(base, tc.base, func(a, b RuleFinding) bool { return a.Evidence == b.Evidence }) {
			t.Errorf("%s: the union changed its base", tc.name)
		}
	}
}

// rel-1-0-10:GAP-0527: trust-literal context demotes some rules to LOW
// detection-only by their surroundings, so a line feed placed at a seam can
// leave a demoted match where the text read as one string is enforceable.
// For every regex-corpus prompt row where a demotable rule is enforceable as
// one string, every two-part split whose line-feed join is demoted must still
// give the one-string finding (rule level) and the one-string verdict
// (regex_only proxy route), on the proxy, hook and session-message routes.
// Rows are corpus rows; cut points are searched, nothing is written out.
func TestPromptSplitTrustLiteralKeepsTheStrongerFinding(t *testing.T) {
	inspector := newPartJoinInspector(t, "regex_only")
	generation := snapshotRulePackGeneration("")
	finding := func(text, rule string) *RuleFinding {
		for _, f := range scanContentRuleCategoryWithGeneration(generation, text, "", ruleContentScopeUntrusted, "") {
			if f.RuleID == rule {
				return &f
			}
		}
		return nil
	}
	strong := func(f *RuleFinding) bool { return f != nil && f.contributesToEnforcement() }
	verdictOf := func(messages []ChatMessage) string {
		raw := promptInspectText(messages)
		v := inspectPromptWithRawRecheck(context.Background(), inspector, promptInspectionText(raw), raw, messages, "model", "action")
		if v == nil {
			return "NONE/allow"
		}
		return v.Severity + "/" + v.Action
	}
	localOf := func(v *ScanVerdict) string {
		if v == nil {
			return "NONE/allow"
		}
		return v.Severity + "/" + v.Action
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"})
	hook := func(message any) agentHookResponse {
		t.Helper()
		return api.evaluateAgentHook(t.Context(), normalizeAgentHookRequestWithProfile("hermes", map[string]interface{}{
			"hook_event_name": "pre_llm_call", "session_id": "sess-partjoin", "prompt": message,
		}, profile))
	}
	splits := 0
	for _, rule := range []string{"TRUST-DELIMITER", "TRUST-PROMPT-EXTRACT", "TRUST-FICTIONAL"} {
		for _, row := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
			if row.Direction != "" && row.Direction != "prompt" {
				continue
			}
			whole := finding(row.Content, rule)
			if !strong(whole) {
				continue
			}
			wholeVerdict := verdictOf([]ChatMessage{{Role: "user", Content: row.Content}})
			wholeLocal := localOf(scanLocalPatternsWithActivation("prompt", row.Content, generation, nil))
			wholeHook := hook(row.Content)
			for i := 1; i < len(row.Content); i++ {
				if !utf8.RuneStart(row.Content[i]) {
					continue
				}
				if f := finding(row.Content[:i]+"\n"+row.Content[i:], rule); f == nil || strong(f) {
					continue
				}
				splits++
				parts := []string{row.Content[:i], row.Content[i:]}
				messages := partJoinChatMessages(t, string(mustJSON(t, []map[string]any{{"role": "user", "content": partJoinBlocks("text", parts)}})))
				raw := promptInspectText(messages)
				var got *RuleFinding
				for _, f := range scanProxyContentRules(withPromptPartsView(context.Background(), "prompt", raw, messages), raw) {
					if f.RuleID == rule {
						got = &f
					}
				}
				if !strong(got) || got.Severity != whole.Severity {
					t.Errorf("%s %s cut %d: proxy rule scan keeps %+v, one string is %s", rule, row.ID, i, got, whole.Severity)
				}
				if v := verdictOf(messages); v != wholeVerdict {
					t.Errorf("%s %s cut %d: proxy verdict %s, one string %s", rule, row.ID, i, v, wholeVerdict)
				}
				blocks := string(mustJSON(t, partJoinBlocks("text", parts)))
				if v := localOf(sessionPromptLocalVerdict(blocks, generation, nil)); v != wholeLocal {
					t.Errorf("%s %s cut %d: session verdict %s, one string %s", rule, row.ID, i, v, wholeLocal)
				}
				if got := hook(partJoinBlocks("text", parts)); got.Severity != wholeHook.Severity || got.Action != wholeHook.Action {
					t.Errorf("%s %s cut %d: hook %s/%s, one string %s/%s", rule, row.ID, i, got.Severity, got.Action, wholeHook.Severity, wholeHook.Action)
				}
			}
		}
	}
	if splits == 0 {
		t.Fatal("no split leaves a demoted line-feed match; the search no longer covers GAP-0527")
	}
	t.Logf("demoted line-feed splits checked: %d", splits)
}
