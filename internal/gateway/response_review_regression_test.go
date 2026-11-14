// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// s7-resprev (review round 1 of s7/response 7f8d355c83) repros. Each test
// asserts the behaviour the branch claims; a failure is a finding. Secrets
// come from the existing rule fixtures (secretRuleTruePositives); no new
// attack text. Output never prints a fixture value.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func resprevSecret(t *testing.T) string {
	t.Helper()
	for _, fx := range secretRuleTruePositives() {
		if fx.wantID == "SEC-GITHUB-TOKEN" {
			return fx.input
		}
	}
	t.Fatal("GitHub token fixture missing")
	return ""
}

func resprevPEMHeader(t *testing.T) string {
	t.Helper()
	for _, fx := range secretRuleTruePositives() {
		if i := strings.Index(fx.input, "-----BEGIN "); i >= 0 {
			line := fx.input[i:]
			if nl := strings.IndexByte(line, '\n'); nl > 0 {
				return line[:nl+1]
			}
		}
	}
	t.Skip("no PEM fixture")
	return ""
}

// R1: invisible separators outside Unicode Cf (Hangul fillers, Khmer
// inherent vowels) are in stripZeroWidth but trustPatternText leaves them, so
// folded == "" and messageRuleFindings returns before the secret pass.
func TestResprevSecretThroughNonCfInvisibleSeparators(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	missed, total := map[string]int{}, 0
	for _, fx := range secretRuleTruePositives() {
		if strings.Contains(fx.input, "-----BEGIN") {
			continue
		}
		for _, sep := range []string{"\u200b", "\u3164", "\uffa0", "\u115f", "\u17b4"} {
			text := spliceZeroWidth(fx.input, sep, 7)
			total++
			for name, findings := range map[string][]string{
				"hook prompt": api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt")).Findings,
				"completion":  insp.Inspect(ctx, "completion", text, nil, "model", "observe").Findings,
			} {
				found := false
				for _, f := range findings {
					found = found || strings.HasPrefix(f, fx.wantID+":")
				}
				if !found {
					missed[fmt.Sprintf("%s U+%04X", name, []rune(sep)[0])]++
					t.Errorf("%s with U+%04X every 7 runes: %s misses %s", fx.name, []rune(sep)[0], name, fx.wantID)
				}
			}
		}
	}
	t.Logf("cases %d, missed %v", total, missed)
}

func resprevPassthrough(t *testing.T, provider, path string, frames []string) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for _, f := range frames {
			_, _ = w.Write([]byte(f))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer upstream.Close()
	orig := providerDomains
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{"127.0.0.1", provider})
	defer func() { providerDomains = orig }()
	_, insp := streamGuardTestCheck()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	body := mustJSON(t, map[string]interface{}{
		"model": "m", "stream": true, "max_tokens": 64,
		"messages": []map[string]interface{}{{"role": "user", "content": "summarize the change"}},
	})
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test-upstream")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	return rec.Body.String()
}

func oaiFrame(t *testing.T, prefix, content string) string {
	b, _ := json.Marshal(map[string]interface{}{"choices": []map[string]interface{}{{"index": 0, "delta": map[string]string{"content": content}}}})
	return prefix + string(b) + "\n\n"
}

// R2 control: the same secret in a normal frame is withheld.
func TestResprevPassthroughControlBlocks(t *testing.T) {
	secret := resprevSecret(t)
	out := resprevPassthrough(t, "openai", "/v1/passthrough-stream", []string{
		oaiFrame(t, "data: ", streamGuardFiller(600)), oaiFrame(t, "data: ", "\n"+secret+"\n"), "data: [DONE]\n\n",
	})
	if strings.Contains(out, secret) {
		t.Fatalf("control: secret released")
	}
}

// R2: an SSE line longer than maxPendingLineBytes (1 MiB) is forwarded with
// no check and no finding (silent cap, ONE BOUND RULE).
func TestResprevPassthroughLongLineIsChecked(t *testing.T) {
	secret := resprevSecret(t)
	out := resprevPassthrough(t, "openai", "/v1/passthrough-stream", []string{
		oaiFrame(t, "data: ", streamGuardFiller(1100<<10)+"\n"+secret+"\n"), "data: [DONE]\n\n",
	})
	if strings.Contains(out, secret) {
		t.Errorf("a >1 MiB SSE line released the secret unchecked (%d bytes out)", len(out))
	}
}

// R3: SSE allows "data:" with no space; the passthrough parser needs "data: ".
func TestResprevPassthroughDataWithoutSpaceIsChecked(t *testing.T) {
	secret := resprevSecret(t)
	out := resprevPassthrough(t, "openai", "/v1/passthrough-stream", []string{
		oaiFrame(t, "data:", streamGuardFiller(600)), oaiFrame(t, "data:", "\n"+secret+"\n"), "data:[DONE]\n\n",
	})
	if strings.Contains(out, secret) {
		t.Errorf("data: frames without the space released the secret unchecked")
	}
}

func anthFrame(t *testing.T, delta map[string]string) string {
	b, _ := json.Marshal(map[string]interface{}{"type": "content_block_delta", "index": 0, "delta": delta})
	return "event: content_block_delta\ndata: " + string(b) + "\n\n"
}

// R4: Anthropic thinking_delta and input_json_delta text is never read.
func TestResprevPassthroughAnthropicThinkingAndToolInputAreChecked(t *testing.T) {
	secret := resprevSecret(t)
	for name, delta := range map[string]map[string]string{
		"text (control)": {"type": "text_delta", "text": "\n" + secret + "\n"},
		"thinking":       {"type": "thinking_delta", "thinking": "\n" + secret + "\n"},
		"tool input":     {"type": "input_json_delta", "partial_json": `{"note":"` + secret + `"}`},
	} {
		out := resprevPassthrough(t, "anthropic", "/v1/messages", []string{
			anthFrame(t, map[string]string{"type": "text_delta", "text": streamGuardFiller(600)}),
			anthFrame(t, delta),
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		})
		if strings.Contains(out, secret) {
			t.Errorf("anthropic %s delta: secret released unchecked", name)
		}
	}
}

// R5: n>1 choices interleaved token by token: the guard reads one text, so a
// secret in choice 0 is split by choice 1's tokens and no rule matches.
func TestResprevMultiChoiceInterleavedSecretIsBlocked(t *testing.T) {
	secret := resprevSecret(t)
	other := streamGuardFiller(len(secret) * 2)
	chunks := []StreamChunk{{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}}}}
	text0 := "\n" + secret + "\n"
	for off, j := 0, 0; off < len(text0); off, j = off+4, j+4 {
		end := min(off+4, len(text0))
		chunks = append(chunks,
			StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: text0[off:end]}}}},
			StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4", Choices: []ChatChoice{{Index: 1, Delta: &ChatMessage{Content: other[j : j+4]}}}},
		)
	}
	_, insp := streamGuardTestCheck()
	proxy := newTestProxy(t, &mockProvider{streamChunks: chunks}, insp, "action")
	rec := postChat(t, proxy, mustJSON(t, map[string]interface{}{
		"model": "gpt-4", "stream": true, "n": 2,
		"messages": []map[string]interface{}{{"role": "user", "content": "summarize the change"}},
	}))
	var got0 strings.Builder
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk StreamChunk
		if json.Unmarshal([]byte(data), &chunk) == nil {
			for _, c := range chunk.Choices {
				if c.Index == 0 && c.Delta != nil {
					got0.WriteString(c.Delta.Content)
				}
			}
		}
	}
	if strings.Contains(got0.String(), secret) {
		t.Errorf("n=2 interleaved stream: choice 0 delivered the secret unchecked")
	}
}

// R6: raw-forward frames carry reasoning fields the parser never reads.
func TestResprevRawForwardReasoningIsChecked(t *testing.T) {
	secret := resprevSecret(t)
	for name, field := range map[string]string{"content (control)": "content", "reasoning_content": "reasoning_content", "reasoning": "reasoning"} {
		frame, _ := json.Marshal(map[string]interface{}{"id": "s1", "object": "chat.completion.chunk",
			"choices": []map[string]interface{}{{"index": 0, "delta": map[string]string{field: "\n" + secret + "\n"}}}})
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: " + string(frame) + "\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		}))
		registerRawForwardProviderDomain(t, upstream.URL, "openai")
		allowRawForwardPrivateTargets(t)
		_, insp := streamGuardTestCheck()
		proxy := newTestProxy(t, &mockProvider{}, insp, "action")
		srv := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
		body := mustJSON(t, map[string]interface{}{"model": "gpt-4", "stream": true,
			"messages": []map[string]interface{}{{"role": "user", "content": "stream"}}})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", upstream.URL)
		req.Header.Set("X-AI-Auth", "Bearer sk-test")
		client := srv.Client()
		client.Timeout = 10 * time.Second
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all, _ := io.ReadAll(bufio.NewReader(resp.Body))
		resp.Body.Close()
		srv.Close()
		upstream.Close()
		if strings.Contains(string(all), secret) {
			t.Errorf("raw forward %s: secret released unchecked", name)
		}
	}
}

// R7: an unclosed private-key header holds the rest of the stream (up to the
// 64 KiB PEM bound) and every check rescans from the header: cost and held
// bytes against the same stream without the header.
func TestResprevOpenPEMHeaderHoldAndCost(t *testing.T) {
	header := resprevPEMHeader(t)
	check, _ := streamGuardTestCheck()
	filler := streamGuardFiller(60 << 10)
	for _, name := range []string{"plain", "open header"} {
		text := "Example key layout:\n" + filler
		if name == "open header" {
			text = "Example key layout:\n" + header + filler
		}
		guard := newCompletionStreamGuard(check, streamGuardScanEvery)
		start := time.Now()
		maxHeld := 0
		for off := 0; off < len(text); off += 24 {
			end := min(off+24, len(text))
			_, v := guard.Push(text[off:end], []byte(text[off:end]))
			if v != nil {
				t.Fatalf("%s blocked", name)
			}
			maxHeld = max(maxHeld, guard.Held())
		}
		_, _ = guard.Finish()
		t.Logf("%s: %d bytes, %d scans, max held %d bytes, %v", name, len(text), guard.Scans(), maxHeld, time.Since(start))
	}
}

// R8: the five removed proxy-only shapes (base guardrail.go
// secretPatternDetectors) with synthetic values: does the rule pack find each
// one on a completion and on a hook prompt? Inputs of the removed tests
// (normalize_test.go, triage_normalize_test.go) included.
func TestResprevRemovedProxyShapesStillFound(t *testing.T) {
	val := func(seed, n int) string {
		const a = "A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5U7v9W0x2Y4z6"
		var b strings.Builder
		for i := 0; b.Len() < n; i++ {
			b.WriteByte(a[(seed*7+i*5)%len(a)])
		}
		return b.String()
	}
	cases := map[string]string{
		"token colon":         "Token: " + val(1, 24),
		"token equals quoted": "token = '" + val(2, 28) + "'",
		"password":            "password=" + val(3, 10),
		"passwd":              "passwd: " + val(4, 12),
		"pwd":                 "pwd=" + val(5, 9),
		"api_key":             "api_key=" + val(6, 20),
		"apikey":              "apikey: " + val(7, 22),
		"api-key":             "api-key=" + val(8, 18),
		"bearer":              "Authorization: Bearer " + val(9, 32),
		"aws secret":          "aws_secret_access_key=" + val(11, 40),
		"removed test 1":      "api_key=q7V2m9X4k8P6r3T1w5Y0n8C4",
		"removed test 2":      "Bearer eyJhbGciOiJIUzI1NiJ9.q7V2m9X4k8P6r3T1w5Y0.n8C4x6Z2",
		"removed test 3":      "token​=​ A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1",
	}
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	for name, text := range cases {
		for _, wrap := range []string{"%s", "Here is the config:\n%s\n", "export %s"} {
			in := fmt.Sprintf(wrap, text)
			c := insp.Inspect(ctx, "completion", in, nil, "model", "action")
			h := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(in, "prompt"))
			rules, _ := verdictRuleIDs(c.Findings)
			hrules, _ := verdictRuleIDs(h.Findings)
			t.Logf("%-20s wrap=%q completion %s/%s %v | hook prompt %s/%s %v", name, strings.ReplaceAll(wrap, "\n", "|"), c.Severity, c.Action, rules, h.Severity, h.Action, hrules)
			if len(rules) == 0 {
				t.Errorf("%s (wrap %q): no rule-pack finding on a completion (the removed proxy detector found it)", name, wrap)
			}
		}
	}
}

func TestResprevRemovedShapesDetail(t *testing.T) {
	val := func(seed, n int) string {
		const a = "A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5U7v9W0x2Y4z6"
		var b strings.Builder
		for i := 0; b.Len() < n; i++ {
			b.WriteByte(a[(seed*7+i*5)%len(a)])
		}
		return b.String()
	}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	for _, name := range []string{"password", "pwd", "passwd", "PASSWORD", "db_password", "Bearer", "bearer token", "curl -H 'Authorization: Bearer"} {
		for _, n := range []int{8, 10, 12, 16, 24, 32} {
			hits := 0
			for seed := 0; seed < 10; seed++ {
				sep := "="
				if strings.HasPrefix(name, "Bearer") || strings.HasPrefix(name, "bearer") || strings.HasPrefix(name, "curl") {
					sep = " "
				}
				c := insp.Inspect(ctx, "completion", name+sep+val(seed, n), nil, "model", "action")
				if r, _ := verdictRuleIDs(c.Findings); len(r) > 0 {
					hits++
				}
			}
			t.Logf("%-32s len %2d: %d/10 found", name, n, hits)
		}
	}
}

// R9 (Q2): on real traces, which secret findings does the invisible-character
// pass add that the raw pass does not have? Reads RESPREV_TRACES (JSONL files,
// comma-separated); prints counts and rule IDs only.
func TestResprevInvisiblePassOnTraces(t *testing.T) {
	paths := os.Getenv("RESPREV_TRACES")
	if paths == "" {
		t.Skip("RESPREV_TRACES not set")
	}
	for _, profile := range []string{"default", "strict"} {
		gen := packGenerationForProfile(t, profile)
		for _, path := range strings.Split(paths, ",") {
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 1<<20), 256<<20)
			rows, withInvisible, withNew := 0, 0, 0
			newIDs := map[string]int{}
			for sc.Scan() {
				rows++
				var row map[string]interface{}
				if json.Unmarshal(sc.Bytes(), &row) != nil {
					continue
				}
				var texts []string
				var walk func(v interface{})
				walk = func(v interface{}) {
					switch x := v.(type) {
					case string:
						if stripZeroWidth(x) != x {
							texts = append(texts, x)
						}
					case []interface{}:
						for _, e := range x {
							walk(e)
						}
					case map[string]interface{}:
						for _, e := range x {
							walk(e)
						}
					}
				}
				walk(row["payload"])
				if len(texts) == 0 {
					continue
				}
				withInvisible++
				added := false
				for _, s := range texts {
					raw := map[string]bool{}
					for _, f := range scanUntrustedContentRules(gen, s) {
						raw[f.RuleID] = true
					}
					folded := ""
					if v := trustPatternText(s); v != s {
						folded = v
					}
					base := map[string]bool{}
					for _, f := range messageRuleFindings(gen, s, "", ruleContentScopeUntrusted, true) {
						base[f.RuleID] = true
					}
					if folded != "" {
						for _, f := range scanRuleGeneration(gen, folded, "message", ruleScanOptions{contentScope: ruleContentScopeUntrusted, onlyCategory: "trust-exploit"}) {
							base[f.RuleID] = true
						}
					}
					for id := range raw {
						if !base[id] {
							newIDs[id]++
							added = true
						}
					}
				}
				if added {
					withNew++
				}
			}
			f.Close()
			t.Logf("%s %s: %d rows, %d with invisible characters, %d gain a finding from the invisible pass %v", profile, filepathBase(path), rows, withInvisible, withNew, newIDs)
		}
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// R10 (Q5): proxy prompt check vs hook prompt check on the regex suite: list
// every divergence (rule IDs or severity), by rule.
func TestResprevPromptParityDivergences(t *testing.T) {
	cases := readJSONL[regexCase](t, "regex", "corpus.jsonl")
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	n, sev, ids := 0, map[string]int{}, map[string]int{}
	for _, c := range cases {
		if c.Direction != "prompt" && c.Direction != "completion" {
			continue
		}
		n++
		hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(c.Content, "prompt"))
		v := insp.Inspect(ctx, "prompt", c.Content, nil, "model", "observe")
		hr, _ := verdictRuleIDs(hook.Findings)
		pr, local := verdictRuleIDs(v.Findings)
		if !slices.Equal(hr, pr) {
			ids[fmt.Sprintf("%v vs hook %v", pr, hr)]++
		}
		if v.Severity != hook.Severity {
			sev[fmt.Sprintf("proxy %s hook %s rules %v local %d", v.Severity, hook.Severity, hr, len(local))]++
		}
	}
	t.Logf("%d cases; rule-id divergences %v", n, ids)
	for k, c := range sev {
		t.Logf("severity divergence x%d: %s", c, k)
	}
}
