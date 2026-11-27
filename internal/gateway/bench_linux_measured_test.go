// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// These five benchmarks run only with an opt-in flag or environment variable
// (-hookbench, DC_INSPECT_BENCH, DC_STREAM_LATENCY_OUT, the cascade and judge
// bench switches). They are measured on the Linux bench boxes (owner 2026-11-15:
// no manual benchmarks on the Windows test hosts), so they are not built for
// Windows and the native Windows selector never lists them (GAP-1615). Linux and
// macOS select them by name as before.

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// hookBench turns on TestAgentHookBenignPreToolUseCost.
var hookBench = flag.Bool("hookbench", false, "measure the per-hook gateway cost (TestAgentHookBenignPreToolUseCost)")

// TestAgentHookBenignPreToolUseCost measures one benign Claude Code
// PreToolUse through the gateway handler with a real audit store (the
// per-hook gateway cost of the r106 performance audit). It runs only with
// the -hookbench test flag: go test ./internal/gateway -run
// TestAgentHookBenignPreToolUseCost -count=1 -v -args -hookbench
// (add -cpuprofile or -memprofile before -args for a profile).
func TestAgentHookBenignPreToolUseCost(t *testing.T) {
	if !*hookBench {
		t.Skip("pass -args -hookbench to measure the per-hook gateway cost")
	}
	fixture := newAuditFailureHookFixture(t, "closed")
	cwd := t.TempDir()
	payloads := map[string]func(int) []byte{
		"bash-echo": func(i int) []byte {
			return mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-bench", "cwd": cwd,
				"tool_name": "Bash", "tool_use_id": fmt.Sprintf("toolu_bench_%d", i), "tool_input": map[string]any{"command": "echo ok"}})
		},
		"read-file": func(i int) []byte {
			return mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-bench", "cwd": cwd,
				"tool_name": "Read", "tool_use_id": fmt.Sprintf("toolu_read_%d", i), "tool_input": map[string]any{"file_path": cwd + "/README.md"}})
		},
	}
	for _, name := range []string{"bash-echo", "read-file"} {
		build := payloads[name]
		i := 0
		result := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				i++
				recorder := httptest.NewRecorder()
				fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(build(i))))
				if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"allow"`)) {
					b.Fatalf("status %d: %.300s", recorder.Code, recorder.Body.String())
				}
			}
		})
		info, _ := os.Stat(fixture.path)
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		wal, _ := os.Stat(fixture.path + "-wal")
		if wal != nil {
			size += wal.Size()
		}
		t.Logf("%s: n=%d %s %s; audit db+wal now %d bytes after %d hooks", name, result.N, result.T/time.Duration(max(result.N, 1)), result.MemString(), size, i)
	}
}

// TestInspectStdinScriptCostBenchmark is the timing guard of GAP-1088: the
// inspect of a call that hands a script to a shell on its standard input
// (a here-string or a heredoc), read by id from the actionfacts corpus, next
// to a call of the same corpus that does not. After the stdin script reading
// (rel-1-0-10:GAP-0980) these calls cost about 4x the rest of the corpus and
// under -race sat 15 ms from the 200 ms inspect scan deadline of
// TestDefenseClawControlFiveTiers.
//
// It prints ns/op and never fails on time (a time bound is flaky); it runs
// only with DC_INSPECT_BENCH=1:
//
//	DC_INSPECT_BENCH=1 go test -run ^TestInspectStdinScriptCostBenchmark$ -v ./internal/gateway
func TestInspectStdinScriptCostBenchmark(t *testing.T) {
	if os.Getenv("DC_INSPECT_BENCH") != "1" {
		t.Skip("set DC_INSPECT_BENCH=1 to time the inspect of the stdin script rows")
	}
	file, err := os.Open("../actionfacts/testdata/defenseclaw_control.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	commands := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r struct{ ID, Command string }
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		commands[r.ID] = r.Command
	}
	a := gap0437Server(t, gap0437Packs[0], "openclaw", "action")
	workdir := t.TempDir()
	warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
		"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": workdir},
	})
	// g596r2-k160 is a here-string script, g596b-t20 a heredoc script, and
	// g596b-t21 a call of the same corpus with no stdin script (the baseline).
	ids := []string{"g596r2-k160", "g596b-t20", "g596b-t21"}
	if only := os.Getenv("DC_INSPECT_BENCH_ROWS"); only != "" {
		ids = strings.Split(only, ",")
	}
	for _, id := range ids {
		command, ok := commands[id]
		if !ok {
			t.Fatalf("corpus row %s is missing", id)
		}
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				gap0437Inspect(t, a, workdir, command)
			}
		})
		t.Logf("%s: %d ns/op over %d runs", id, result.NsPerOp(), result.N)
	}
}

// TestStreamLatencyReport measures a streamed completion through the proxy
// (rel-1-0-10:GAP-0212 latency bar): time to first byte and total stream
// time at the client, p50 and p95, for the Anthropic and OpenAI Responses
// passthrough and the OpenAI chat /llm route, on a clean stream and on one
// with a finding in its last delta. The upstream stub sends 160 deltas of
// 24 bytes, one every 5 ms. The inspector is the local guardrail inspector
// (its regex cost included), with a benign marker as the finding. It runs
// only with DC_STREAM_LATENCY_OUT=<file> (one JSON line per cell), so a rel
// worktree can run the same file for the before side.
func TestStreamLatencyReport(t *testing.T) {
	out := os.Getenv("DC_STREAM_LATENCY_OUT")
	if out == "" {
		t.Skip("set DC_STREAM_LATENCY_OUT to run the stream latency report")
	}
	const (
		marker = "zq-latency-marker-51c2"
		deltas = 160
		size   = 24
		gap    = 5 * time.Millisecond
		runs   = 21
	)
	text := func(finding bool) []string {
		const prose = "the stream carries plain words about lists and maps and loops. "
		var sb strings.Builder
		for sb.Len() < deltas*size {
			sb.WriteString(prose)
		}
		s := sb.String()[:deltas*size]
		var d []string
		for i := 0; i < len(s); i += size {
			d = append(d, s[i:i+size])
		}
		if finding {
			d[len(d)-1] = marker
		}
		return d
	}
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	sse := map[string]func(string) string{
		"anthropic": func(d string) string {
			return "event: content_block_delta\ndata: " + js(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": d}}) + "\n\n"
		},
		"responses": func(d string) string {
			return "event: response.output_text.delta\ndata: " + js(map[string]any{"type": "response.output_text.delta", "delta": d}) + "\n\n"
		},
	}
	terminal := map[string]string{
		"anthropic": "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		"responses": "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
	}
	path := map[string]string{"anthropic": "/v1/messages", "responses": "/v1/responses", "chat": "/v1/chat/completions"}
	pct := func(xs []time.Duration, p float64) float64 {
		s := append([]time.Duration(nil), xs...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return float64(s[min(len(s)-1, int(p*float64(len(s)-1)+0.5))].Microseconds()) / 1000
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	orig := providerDomains
	t.Cleanup(func() { providerDomains = orig })
	for _, format := range []string{"anthropic", "responses", "chat"} {
		provider := "anthropic"
		if format != "anthropic" {
			provider = "openai"
		}
		providerDomains = append(append([]providerDomainEntry(nil), orig...), providerDomainEntry{domain: "127.0.0.1", name: provider})
		for _, finding := range []bool{false, true} {
			d := text(finding)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fl := w.(http.Flusher)
				for _, x := range d {
					time.Sleep(gap)
					_, _ = io.WriteString(w, sse[format](x))
					fl.Flush()
				}
				_, _ = io.WriteString(w, terminal[format])
			}))
			insp := &latencyMarkerInspector{inner: NewGuardrailInspector("local", nil, nil), marker: marker}
			prov := &latencyStreamProvider{deltas: d, gap: gap}
			proxy := newTestProxy(t, prov, insp, "action")
			var handler http.HandlerFunc = proxy.handlePassthrough
			if format == "chat" {
				handler = proxy.handleChatCompletion
			}
			front := httptest.NewServer(handler)
			var ttfb, total []time.Duration
			blocked := 0
			for i := 0; i < runs; i++ {
				body, _ := json.Marshal(map[string]any{"model": "m", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
				req, _ := http.NewRequest(http.MethodPost, front.URL+path[format], bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if format != "chat" {
					req.Header.Set("X-DC-Target-URL", up.URL)
					req.Header.Set("X-AI-Auth", "Bearer sk-test-upstream")
				}
				t0 := time.Now()
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				one := make([]byte, 1)
				if _, err := io.ReadFull(resp.Body, one); err != nil {
					t.Fatalf("%s: no first byte: %v", format, err)
				}
				ttfb = append(ttfb, time.Since(t0))
				rest, _ := io.ReadAll(resp.Body)
				total = append(total, time.Since(t0))
				resp.Body.Close()
				if bytes.Contains(rest, []byte("blocked")) || (format != "chat" && !bytes.HasSuffix(rest, []byte(terminal[format]))) {
					blocked++
				}
			}
			front.Close()
			up.Close()
			row := map[string]any{"format": format, "finding": finding, "runs": runs, "deltas": deltas, "delta_bytes": size, "gap_ms": gap.Milliseconds(),
				"ttfb_p50_ms": pct(ttfb, 0.5), "ttfb_p95_ms": pct(ttfb, 0.95), "total_p50_ms": pct(total, 0.5), "total_p95_ms": pct(total, 0.95), "blocked": blocked}
			line, _ := json.Marshal(row)
			fmt.Fprintln(f, string(line))
			t.Log(string(line))
		}
	}
}

type latencyMarkerInspector struct {
	inner  ContentInspector
	marker string
}

func (l *latencyMarkerInspector) mark(direction, content string, v *ScanVerdict) *ScanVerdict {
	if direction == "completion" && strings.Contains(content, l.marker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "latency marker", Findings: []string{"test:latency-marker"}}
	}
	return v
}

func (l *latencyMarkerInspector) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return l.mark(direction, content, l.inner.Inspect(ctx, direction, content, messages, model, mode))
}

func (l *latencyMarkerInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return l.mark(direction, content, l.inner.InspectMidStream(ctx, direction, content, messages, model, mode))
}

func (l *latencyMarkerInspector) SetScannerMode(string) {}

func (l *latencyMarkerInspector) SetHILTConfig(bool, string) {}

type latencyStreamProvider struct {
	mockProvider
	deltas []string
	gap    time.Duration
}

func (l *latencyStreamProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, d := range l.deltas {
		select {
		case <-time.After(l.gap):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "m", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: d}}}})
	}
	stop := "stop"
	cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "m", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &stop}}})
	return &ChatUsage{}, nil
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
		api.scannerCfg.Guardrail.Cascade.Policy.TimeoutMs = 0 // the production budget (5 ms)
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

type corpusJudgeMetadata struct {
	SchemaVersion   string    `json:"schema_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	Corpus          string    `json:"corpus"`
	CorpusSHA256    string    `json:"corpus_sha256"`
	Model           string    `json:"model"`
	BaseURL         string    `json:"base_url"`
	RulePack        string    `json:"rule_pack"`
	CaseCount       int       `json:"case_count"`
	InvocationCount int       `json:"invocation_count"`
	WallClockMS     float64   `json:"wall_clock_ms"`
	Temperature     float64   `json:"temperature"`
	ResponseFormat  string    `json:"response_format"`
	ProductionPath  string    `json:"production_path"`
	Concurrency     int       `json:"concurrency"`
	BedrockRegion   string    `json:"bedrock_region,omitempty"`
	BedrockAuthMode string    `json:"bedrock_auth_mode,omitempty"`
}

func TestLLMJudgeDeterministicCorpus(t *testing.T) {
	if os.Getenv("GUARDRAIL_BENCHMARK_LLM") != "1" {
		t.Skip("set GUARDRAIL_BENCHMARK_LLM=1 to run the production-path LLM judge benchmark")
	}
	corpusPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_CORPUS"))
	outputPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_OUTPUT"))
	model := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_MODEL"))
	if corpusPath == "" || outputPath == "" || model == "" {
		t.Fatal("DEFENSECLAW_JUDGE_BENCHMARK_CORPUS, _OUTPUT, and _MODEL are required")
	}
	baseURL := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BASE_URL"))
	if baseURL == "" {
		baseURL = "http://127.0.0.1:11434"
	}
	rulePackPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RULE_PACK"))
	rulePack, err := guardrail.LoadRulePack(rulePackPath)
	if err != nil {
		t.Fatalf("load rule pack: %v", err)
	}
	if !strings.Contains(model, "/") {
		model = "ollama/" + model
	}
	concurrency := benchmarkConcurrency(t)

	cases, corpusData, err := readCorpusJudgeCases(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.JudgeConfig{
		Enabled: true, Injection: true, PII: true, PIIPrompt: true,
		PIICompletion: true, Exfil: true, ToolInjection: true,
		Timeout: 120, AdjudicationTimeout: 120,
	}
	llm := benchmarkLLMConfig(model, baseURL)
	judge := NewLLMJudge(cfg, llm, "", rulePack, nil)
	if judge == nil {
		t.Fatal("production LLM judge failed to initialize")
	}
	recorder := &judgeBenchmarkProvider{delegate: judge.provider}
	judge.provider = recorder

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatal(err)
	}
	startIndex := 0
	priorInvocations := 0
	priorWallClockMS := float64(0)
	openFlags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	if os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RESUME") == "1" {
		prior, readErr := readCorpusJudgePredictions(outputPath)
		if readErr != nil {
			t.Fatalf("resume prior predictions: %v", readErr)
		}
		if os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RETRY_FAILURES") == "1" {
			prefix := successfulCorpusJudgePrefix(prior)
			if len(prefix) != len(prior) {
				if err := writeCorpusJudgePredictions(outputPath, prefix); err != nil {
					t.Fatalf("repair failed prediction suffix: %v", err)
				}
				t.Logf("judge benchmark retry: removed %d failed suffix rows", len(prior)-len(prefix))
				prior = prefix
			}
		}
		if len(prior) > len(cases) {
			t.Fatalf("resume output has %d rows for %d cases", len(prior), len(cases))
		}
		for index := range prior {
			if prior[index].CaseID != cases[index].ID || prior[index].Model != model {
				t.Fatalf("resume output row %d does not match corpus/model", index+1)
			}
			if err := validateCorpusJudgeResumeContract(t.Context(), judge, model, cases[index], prior[index]); err != nil {
				t.Fatalf("resume output row %d: %v", index+1, err)
			}
			priorInvocations += prior[index].InvocationCount
			priorWallClockMS += prior[index].EndToEndLatencyMS
		}
		startIndex = len(prior)
		if startIndex > 0 {
			openFlags = os.O_CREATE | os.O_APPEND | os.O_WRONLY
			t.Logf("judge benchmark resume: %d/%d cases, %d prior model calls", startIndex, len(cases), priorInvocations)
		}
	}
	output, err := os.OpenFile(outputPath, openFlags, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(output)
	runStarted := time.Now()
	type indexedPrediction struct {
		index      int
		prediction corpusJudgePrediction
	}
	jobs := make(chan int, concurrency)
	results := make(chan indexedPrediction, concurrency)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				results <- indexedPrediction{
					index:      index,
					prediction: runCorpusJudgeCase(t.Context(), judge, recorder, model, cases[index]),
				}
			}
		}()
	}
	go func() {
		for index := startIndex; index < len(cases); index++ {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	// Preserve corpus order on disk so resume remains a validated prefix even
	// when provider calls complete out of order. The small pending map is also
	// what lets a completed contiguous prefix survive an interrupted large run.
	next := startIndex
	pending := make(map[int]corpusJudgePrediction, concurrency)
	var encodeErr error
	for result := range results {
		pending[result.index] = result.prediction
		for encodeErr == nil {
			prediction, ok := pending[next]
			if !ok {
				break
			}
			if err := encoder.Encode(prediction); err != nil {
				encodeErr = err
				break
			}
			delete(pending, next)
			next++
			if next%10 == 0 || next == len(cases) {
				t.Logf("judge benchmark progress: %d/%d cases, %d model calls", next, len(cases), recorder.count())
			}
		}
	}
	if encodeErr != nil {
		_ = output.Close()
		t.Fatal(encodeErr)
	}
	if next != len(cases) {
		_ = output.Close()
		t.Fatalf("judge benchmark completed %d/%d ordered cases", next, len(cases))
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(corpusData)
	metadata := corpusJudgeMetadata{
		SchemaVersion: "1", GeneratedAt: time.Now().UTC(), Corpus: corpusPath,
		CorpusSHA256: hex.EncodeToString(digest[:]), Model: model, BaseURL: llm.BaseURL,
		RulePack: rulePackPath, CaseCount: len(cases), InvocationCount: priorInvocations + recorder.count(),
		WallClockMS: priorWallClockMS + float64(time.Since(runStarted).Microseconds())/1000,
		Temperature: 0, ResponseFormat: "json_schema",
		ProductionPath: "gateway.LLMJudge.RunJudges/RunToolJudge via Bifrost",
		Concurrency:    concurrency,
	}
	if llm.Bedrock != nil {
		metadata.BedrockRegion = llm.Bedrock.Region
		metadata.BedrockAuthMode = llm.Bedrock.AuthMode
	}
	metadataData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := outputPath + ".meta.json"
	if err := os.WriteFile(metadataPath, append(metadataData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func benchmarkConcurrency(t *testing.T) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY"))
	if raw == "" {
		return 1
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 64 {
		t.Fatalf("DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY must be an integer from 1 through 64, got %q", raw)
	}
	return value
}

func writeCorpusJudgePredictions(path string, predictions []corpusJudgePrediction) error {
	temporary := path + ".repair.tmp"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	for index := range predictions {
		if err := encoder.Encode(predictions[index]); err != nil {
			_ = output.Close()
			_ = os.Remove(temporary)
			return err
		}
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func readCorpusJudgeCases(path string) ([]corpusJudgeCase, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var cases []corpusJudgeCase
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	seen := make(map[string]struct{})
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var benchmarkCase corpusJudgeCase
		if err := json.Unmarshal(scanner.Bytes(), &benchmarkCase); err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if benchmarkCase.SchemaVersion != "1" || strings.TrimSpace(benchmarkCase.ID) == "" {
			return nil, nil, fmt.Errorf("%s:%d: invalid case identity", path, lineNumber)
		}
		if _, exists := seen[benchmarkCase.ID]; exists {
			return nil, nil, fmt.Errorf("%s:%d: duplicate case ID %q", path, lineNumber, benchmarkCase.ID)
		}
		seen[benchmarkCase.ID] = struct{}{}
		cases = append(cases, benchmarkCase)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if len(cases) == 0 {
		return nil, nil, errors.New("corpus is empty")
	}
	return cases, data, nil
}
