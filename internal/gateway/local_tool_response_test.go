package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type localScoreFunc func(context.Context, string) (float64, error)

func (f localScoreFunc) Scan(c context.Context, s string) (float64, error) { return f(c, s) }
func TestLocalToolResponseModesAndDisabled(t *testing.T) {
	for _, mode := range []string{"action", "observe"} {
		a := testAPIServerWithConfig(t, mode)
		calls := 0
		a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { calls++; return .9, nil }), .5)
		_, v := postInspectToolResponse(t, a, `{"tool":"read","output":"ordinary text"}`)
		want := "block"
		if mode == "observe" {
			want = "allow"
		}
		if v.Action != want || calls != 1 {
			t.Fatalf("%s %+v calls=%d", mode, v, calls)
		}
		if mode == "observe" && (!v.WouldBlock || v.RawAction != "block") {
			t.Fatal(v)
		}
		a.SetLocalToolResponseScanner(nil, .5)
		postInspectToolResponse(t, a, `{"tool":"read","output":"ordinary text"}`)
		if calls != 1 {
			t.Fatal("off scanner called")
		}
	}
}
func TestLocalToolResponseErrorAndNoDowngrade(t *testing.T) {
	a := testAPIServerWithConfig(t, "action")
	a.scannerCfg.Guardrail.BlockAt = "HIGH"
	a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { return 0, errors.New("private data") }), .5)
	_, v := postInspectToolResponse(t, a, `{"tool":"read","output":"ordinary"}`)
	if v.Action != "block" || strings.Contains(v.Reason, "private") {
		t.Fatal(v)
	}
	a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { return 0, nil }), .5)
	_, v = postInspectToolResponse(t, a, `{"tool":"read","output":"my ssn is 078-05-1120"}`)
	if v.Action != "block" {
		t.Fatalf("baseline denial downgraded: %+v", v)
	}
}
func TestLocalToolResponseSeesTailBeforeLegacyTruncation(t *testing.T) {
	a := testAPIServerWithConfig(t, "action")
	seen := false
	a.SetLocalToolResponseScanner(localScoreFunc(func(_ context.Context, s string) (float64, error) {
		seen = strings.HasSuffix(s, "TAIL")
		return .9, nil
	}), .5)
	body, _ := json.Marshal(map[string]string{"tool": "read", "output": strings.Repeat("a", maxInspectContentLen) + "TAIL"})
	// Isolate the boundary from the production regex wall-clock budget: a
	// 256 KiB fixture with every shipped rule is not an SLA/performance test.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool-response", bytes.NewReader(body))
	req = req.WithContext(withPinnedGeneration(req.Context(), &Generation{Config: a.scannerCfg, activeRules: &compiledRulePackCategories{}}))
	response := httptest.NewRecorder()
	a.handleInspectToolResponse(response, req)
	var v ToolInspectVerdict
	if err := json.NewDecoder(response.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if !seen || response.Code != http.StatusOK || v.Action != "block" {
		t.Fatalf("tail missed: seen=%v status=%d verdict=%+v", seen, response.Code, v)
	}
}

func TestLocalToolResponseNativeBoundary(t *testing.T) {
	a := testAPIServerWithConfig(t, "action")
	calls := 0
	a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { calls++; return .9, nil }), .5)
	v := a.inspectMessageContent(context.Background(), &ToolInspectRequest{Tool: "read", Content: "content", Direction: "tool_result"})
	if v.Action != "block" || calls != 1 {
		t.Fatalf("%+v calls=%d", v, calls)
	}
}

func TestLocalToolResponseProxyBoundary(t *testing.T) {
	for _, score := range []float64{.1, .9} {
		for _, user := range []string{"Summarize the tool result.", ""} {
			g := NewGuardrailInspector("local", nil, nil)
			calls := 0
			g.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { calls++; return score, nil }), .5)
			prov := &mockProvider{}
			p := newTestProxy(t, prov, g, "action")
			body, _ := json.Marshal(map[string]any{"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": user}, {"role": "tool", "tool_call_id": "call1", "content": "tool result"}}})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			response := httptest.NewRecorder()
			p.handleChatCompletion(response, req)
			if calls != 1 {
				t.Fatalf("calls=%d", calls)
			}
			if (score < .5) != (prov.lastReq != nil) {
				t.Fatalf("score=%v response=%s", score, response.Body.String())
			}
		}
	}
}

func TestWolfDisabledStartsNothing(t *testing.T) {
	// Invalid executable and asset paths must never be touched on the off path.
	w, err := startWolf(context.Background(), config.WolfConfig{PythonExecutable: "/missing/python", ModelDir: "/missing/model"})
	if err != nil || w != nil {
		t.Fatalf("worker=%v error=%v", w, err)
	}
}

func TestWolfConfigRequiresProcessRestart(t *testing.T) {
	old := config.DefaultConfig()
	next := config.DefaultConfig()
	next.Guardrail.Wolf.Variant = "full"
	if !guardrailNeedsRestart(old, next) {
		t.Fatal("model change must require restart")
	}
	holdGuardrailProcessSettings(&next.Guardrail, old.Guardrail)
	if next.Guardrail.Wolf != old.Guardrail.Wolf {
		t.Fatal("reload changed live model settings")
	}
}

func TestLocalToolResponseRawRecheckCannotClearBlock(t *testing.T) {
	g := NewGuardrailInspector("local", nil, nil)
	g.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { return .9, nil }), .5)
	v := g.InspectWithRawRecheck(context.Background(), "prompt", "safe", "another safe string", []ChatMessage{{Role: "tool", Content: "tool result"}}, "test", "observe")
	// The proxy owns enforcement vs observation; retain the raw block for telemetry.
	if v.Action != "block" || !strings.Contains(v.Reason, "local-model:") {
		t.Fatalf("%+v", v)
	}
}

func TestLocalToolResponseConcurrentBinding(t *testing.T) {
	a := testAPIServerWithConfig(t, "action")
	scanner := localScoreFunc(func(context.Context, string) (float64, error) { return .9, nil })
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				v := a.inspectLocalToolResponse(context.Background(), "tool result")
				if v != nil && v.Action != "block" {
					t.Errorf("unexpected verdict %+v", v)
				}
			}
		}()
	}
	for n := 0; n < 20; n++ {
		a.SetLocalToolResponseScanner(scanner, .5)
		a.SetLocalToolResponseScanner(nil, .5)
	}
	wg.Wait()
}

func TestLocalToolResponseProxyObserveForwards(t *testing.T) {
	g := NewGuardrailInspector("local", nil, nil)
	g.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { return .9, nil }), .5)
	prov := &mockProvider{}
	p := newTestProxy(t, prov, g, "observe")
	body := []byte(`{"model":"gpt-4","messages":[{"role":"tool","tool_call_id":"call1","content":"tool result"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	response := httptest.NewRecorder()
	p.handleChatCompletion(response, req)
	if prov.lastReq == nil {
		t.Fatalf("observe mode blocked forwarding: %s", response.Body.String())
	}
}

func TestLocalToolResponsePreservesBaselineFindingsInObserve(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			a := testAPIServerWithConfig(t, "observe")
			body := `{"tool":"read","output":"my ssn is 078-05-1120"}`
			_, baseline := postInspectToolResponse(t, a, body)
			if len(baseline.Findings) == 0 {
				t.Fatal("fixture did not produce baseline findings")
			}
			a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) {
				if failed {
					return 0, errors.New("runtime unavailable")
				}
				return .9, nil
			}), .5)
			_, v := postInspectToolResponse(t, a, body)
			if v.Action != "allow" || !v.WouldBlock {
				t.Fatalf("%+v", v)
			}
			for _, f := range baseline.Findings {
				if !slices.Contains(v.Findings, f) {
					t.Fatalf("baseline finding %q missing from %v", f, v.Findings)
				}
			}
			if !strings.Contains(v.Reason, "local-model:") {
				t.Fatalf("local verdict missing: %+v", v)
			}
		})
	}
}

func TestLocalToolResponseHistoryRetainsCallerContext(t *testing.T) {
	type key struct{}
	parent := context.WithValue(context.Background(), key{}, "caller")
	g := NewGuardrailInspector("local", nil, nil)
	calls := 0
	g.SetLocalToolResponseScanner(localScoreFunc(func(ctx context.Context, _ string) (float64, error) {
		calls++
		if _, ok := ctx.Deadline(); ok {
			t.Error("unexpected shared history deadline")
		}
		if ctx.Value(key{}) != "caller" {
			t.Error("caller context lost")
		}
		return .1, nil
	}), .5)
	v := g.inspectLocalToolMessages(parent, []ChatMessage{{Role: "tool", Content: "first"}, {Role: "tool", Content: "second"}})
	if v != nil || calls != 2 {
		t.Fatalf("verdict=%+v calls=%d", v, calls)
	}
}

func TestLocalToolResponseHistoryLimitRefusesBeforeScanning(t *testing.T) {
	g := NewGuardrailInspector("local", nil, nil)
	calls := 0
	g.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) { calls++; return .1, nil }), .5)
	messages := []ChatMessage{{Role: "system", Content: "not counted"}}
	for i := 0; i < maxLocalToolMessages; i++ {
		messages = append(messages, ChatMessage{Role: "tool", Content: "fixture"})
	}
	if v := g.inspectLocalToolMessages(context.Background(), messages); v != nil || calls != maxLocalToolMessages {
		t.Fatalf("verdict=%+v calls=%d", v, calls)
	}
	calls = 0
	messages = append(messages, ChatMessage{Role: "TOOL", Content: "over limit"})
	v := g.inspectLocalToolMessages(context.Background(), messages)
	if v == nil || v.Action != "block" || v.Reason != "local-model:tool-message-limit" || calls != 0 {
		t.Fatalf("verdict=%+v calls=%d", v, calls)
	}
	// A preflight refusal must leave the scanner available for the next request.
	if v := g.inspectLocalToolMessages(context.Background(), messages[:2]); v != nil || calls != 1 {
		t.Fatalf("verdict=%+v calls=%d", v, calls)
	}
}

func TestLocalToolResponseDoesNotSkipConfiguredJudge(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			mock := piiCompletionHitProvider()
			a := newToolOutputJudgeServer(t, config.JudgeConfig{Enabled: true, PII: true, PIICompletion: true, HookConnectors: []string{"hermes"}}, "judge_first", mock)
			a.scannerCfg.Guardrail.Mode = "observe"
			a.SetLocalToolResponseScanner(localScoreFunc(func(context.Context, string) (float64, error) {
				if failed {
					return 0, errors.New("unavailable")
				}
				return .9, nil
			}), .5)
			_, v := postInspectToolResponse(t, a, `{"tool":"fetch_url","output":"reach me at test@example.com during the local-lane regression check"}`)
			if len(mock.captured) == 0 || !judgeTaggedFinding(v.Findings) {
				t.Fatalf("configured judge skipped: calls=%d verdict=%+v", len(mock.captured), v)
			}
			if v.Action != "allow" || !v.WouldBlock || !strings.Contains(v.Reason, "local-model:") {
				t.Fatalf("unexpected merged verdict: %+v", v)
			}
		})
	}
}
