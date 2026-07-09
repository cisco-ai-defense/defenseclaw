# Full Semantic Router Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand DefenseClaw's semantic routing engine from keyword-only/static to 14 selection algorithms and 17 signal types, using Ollama for embeddings and the existing LLM Judge for classification calls.

**Architecture:** The routing engine (`internal/routing/`) gets refactored into a signal-based classification pipeline (17 signal evaluators running in parallel), a boolean-expression decision engine, and a pluggable selection algorithm registry (14 algorithms). Signals that need ML use Ollama's embedding API (`/api/embeddings`) or the existing LLM Judge infrastructure. State for adaptive algorithms (Elo, KNN, RL) persists in SQLite via the existing `audit.Store`. The `ModelRouter` interface and gateway wiring remain unchanged.

**Tech Stack:** Go 1.22+, Ollama (embedding + LLM), SQLite (state), existing `LLMJudge` + `config.LLMConfig` infrastructure.

## Global Constraints

- Pure Go — no CGo, Rust, ONNX, or native bindings
- Binary size delta < 5MB
- Routing decision latency budget: < 50ms total (in-process signals < 1ms, embedding signals < 15ms, LLM signals < 300ms but run only when configured)
- Graceful degradation: any signal/algorithm failure returns nil → falls through to default provider
- Thread-safe: all signals and algorithms must be safe for concurrent use
- Config backward-compatible: existing `routing:` configs must still work unchanged

---

## File Structure

### New files (create)

| File | Responsibility |
|------|----------------|
| `internal/routing/signal.go` | `Signal` interface, `SignalOutput` type, `SignalEngine` parallel evaluator |
| `internal/routing/signal_keyword.go` | Keyword signal (refactored from classifier.go) |
| `internal/routing/signal_embedding.go` | Embedding similarity via Ollama `/api/embeddings` |
| `internal/routing/signal_domain.go` | Domain classification via LLM Judge call |
| `internal/routing/signal_complexity.go` | Complexity scoring via LLM Judge call |
| `internal/routing/signal_context_length.go` | Token-count thresholds (in-process) |
| `internal/routing/signal_language.go` | Language detection (in-process heuristic) |
| `internal/routing/signal_structure.go` | Prompt structure analysis (regex) |
| `internal/routing/signal_pii.go` | PII pattern detection (in-process) |
| `internal/routing/signal_conversation.go` | Multi-turn shape (message count, tool loops) |
| `internal/routing/signal_jailbreak.go` | Jailbreak detection (reuses guardrail regex) |
| `internal/routing/signal_modality.go` | Vision/text/tool-use detection |
| `internal/routing/signal_reask.go` | Repeated question detection |
| `internal/routing/signal_user_feedback.go` | Dissatisfaction recognition |
| `internal/routing/signal_event.go` | External event triggers |
| `internal/routing/signal_authz.go` | RBAC group membership |
| `internal/routing/signal_factcheck.go` | Factual verification need |
| `internal/routing/signal_kb.go` | Knowledge-base prototype matching (embedding-based) |
| `internal/routing/selector.go` | `Selector` interface, `SelectorRegistry`, `SelectionContext` |
| `internal/routing/selector_static.go` | Static selection (existing behavior) |
| `internal/routing/selector_elo.go` | Elo-based Bradley-Terry scoring |
| `internal/routing/selector_knn.go` | K-Nearest Neighbor quality-weighted voting |
| `internal/routing/selector_kmeans.go` | KMeans cluster assignment |
| `internal/routing/selector_latency.go` | Latency-aware (p90 tracking) |
| `internal/routing/selector_multifactor.go` | Weighted multi-factor scoring |
| `internal/routing/selector_hybrid.go` | Weighted blend of multiple selectors |
| `internal/routing/selector_routerdc.go` | Dual-contrastive embedding similarity |
| `internal/routing/selector_automix.go` | POMDP cascading with verification |
| `internal/routing/selector_rl.go` | Thompson Sampling with Beta distributions |
| `internal/routing/selector_session.go` | Session continuity wrapper |
| `internal/routing/selector_svm.go` | Stub (requires training data) |
| `internal/routing/selector_mlp.go` | Stub (requires training data) |
| `internal/routing/selector_gmt.go` | Stub (requires graph infrastructure) |
| `internal/routing/decision_tree.go` | Boolean expression tree (AND/OR/NOT recursive) |
| `internal/routing/embedding_client.go` | Ollama embedding client (HTTP, batch) |
| `internal/routing/llm_classifier.go` | LLM-based classification (domain, complexity) via chat completion |
| `internal/routing/state.go` | SQLite state store (Elo scores, KNN history, RL betas) |
| `internal/routing/metrics.go` | Latency tracker, request counter, per-model stats |

### Modified files

| File | Changes |
|------|---------|
| `internal/routing/config.go` | Expand `RoutingConfig` with new signal types, embedding config, algorithm config, decision tree schema |
| `internal/routing/router.go` | Refactor `SemanticRouter` to use `SignalEngine` + `DecisionTree` + `SelectorRegistry` |
| `internal/routing/classifier.go` | Remove (contents move to `signal_keyword.go`) |
| `internal/routing/decision.go` | Remove (replaced by `decision_tree.go`) |
| `internal/config/config.go` | Expand `RoutingConfig` types to match new schema |
| `internal/gateway/model_router_adapter.go` | Update config conversion to pass new fields |

### Test files (create)

| File | Coverage |
|------|----------|
| `internal/routing/signal_test.go` | Signal interface, parallel evaluation, timeout handling |
| `internal/routing/signal_keyword_test.go` | Keyword OR/AND/case/empty |
| `internal/routing/signal_embedding_test.go` | Cosine similarity, mock Ollama, threshold |
| `internal/routing/signal_domain_test.go` | Mock LLM response parsing |
| `internal/routing/signal_complexity_test.go` | Score extraction, fallback |
| `internal/routing/signal_context_length_test.go` | Threshold bands |
| `internal/routing/signal_language_test.go` | Detection accuracy |
| `internal/routing/signal_pii_test.go` | Pattern matching |
| `internal/routing/selector_test.go` | Registry, interface compliance |
| `internal/routing/selector_elo_test.go` | Score updates, decay |
| `internal/routing/selector_knn_test.go` | Neighbor voting, distance |
| `internal/routing/selector_routerdc_test.go` | Cosine scoring against capability embeddings |
| `internal/routing/selector_automix_test.go` | Cascade logic, verification |
| `internal/routing/selector_latency_test.go` | p90 tracking, selection |
| `internal/routing/decision_tree_test.go` | AND/OR/NOT nesting, confidence |
| `internal/routing/embedding_client_test.go` | HTTP mock, batch, error handling |
| `internal/routing/state_test.go` | SQLite CRUD, concurrent access |

---

## Tasks

### Task 1: Signal Interface and Parallel Engine

**Files:**
- Create: `internal/routing/signal.go`
- Test: `internal/routing/signal_test.go`

**Interfaces:**
- Consumes: `Message` type from existing `classifier.go`
- Produces: `Signal` interface (`Name() string`, `Evaluate(ctx, []Message) *SignalOutput`), `SignalOutput` struct (`Name string`, `Fired bool`, `Confidence float64`, `Value string`), `SignalEngine` struct (`Evaluate(ctx, []Message, []Signal) map[string]*SignalOutput`)

- [ ] **Step 1: Write failing test for SignalEngine**

```go
// internal/routing/signal_test.go
package routing

import (
    "context"
    "testing"
    "time"
)

type mockSignal struct {
    name   string
    fired  bool
    delay  time.Duration
}

func (m *mockSignal) Name() string { return m.name }
func (m *mockSignal) Evaluate(ctx context.Context, msgs []Message) *SignalOutput {
    if m.delay > 0 {
        time.Sleep(m.delay)
    }
    return &SignalOutput{Name: m.name, Fired: m.fired, Confidence: 1.0}
}

func TestSignalEngine_EvaluatesAllSignals(t *testing.T) {
    engine := NewSignalEngine(50 * time.Millisecond)
    signals := []Signal{
        &mockSignal{name: "a", fired: true},
        &mockSignal{name: "b", fired: false},
        &mockSignal{name: "c", fired: true},
    }
    results := engine.Evaluate(context.Background(), []Message{{Role: "user", Content: "hello"}}, signals)
    if len(results) != 3 {
        t.Fatalf("expected 3 results, got %d", len(results))
    }
    if !results["a"].Fired {
        t.Error("signal 'a' should have fired")
    }
    if results["b"].Fired {
        t.Error("signal 'b' should not have fired")
    }
}

func TestSignalEngine_TimeoutReturnsPartial(t *testing.T) {
    engine := NewSignalEngine(10 * time.Millisecond)
    signals := []Signal{
        &mockSignal{name: "fast", fired: true, delay: 0},
        &mockSignal{name: "slow", fired: true, delay: 100 * time.Millisecond},
    }
    results := engine.Evaluate(context.Background(), []Message{{Role: "user", Content: "hi"}}, signals)
    if !results["fast"].Fired {
        t.Error("fast signal should be present")
    }
    if _, ok := results["slow"]; ok {
        t.Error("slow signal should have been dropped due to timeout")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/routing/ -run TestSignalEngine -v`
Expected: FAIL — `NewSignalEngine` undefined

- [ ] **Step 3: Implement Signal interface and SignalEngine**

```go
// internal/routing/signal.go
package routing

import (
    "context"
    "sync"
    "time"
)

// Signal evaluates a single classification signal against the input messages.
type Signal interface {
    Name() string
    Evaluate(ctx context.Context, msgs []Message) *SignalOutput
}

// SignalOutput is the result of a single signal evaluation.
type SignalOutput struct {
    Name       string
    Fired      bool
    Confidence float64 // 0.0 to 1.0
    Value      string  // optional: domain name, complexity level, etc.
}

// SignalEngine evaluates signals concurrently with a timeout.
type SignalEngine struct {
    timeout time.Duration
}

func NewSignalEngine(timeout time.Duration) *SignalEngine {
    return &SignalEngine{timeout: timeout}
}

// Evaluate runs all signals in parallel, returning results within the timeout.
func (e *SignalEngine) Evaluate(ctx context.Context, msgs []Message, signals []Signal) map[string]*SignalOutput {
    ctx, cancel := context.WithTimeout(ctx, e.timeout)
    defer cancel()

    results := make(map[string]*SignalOutput, len(signals))
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, s := range signals {
        wg.Add(1)
        go func(sig Signal) {
            defer wg.Done()
            out := sig.Evaluate(ctx, msgs)
            if out == nil {
                return
            }
            select {
            case <-ctx.Done():
                return
            default:
            }
            mu.Lock()
            results[out.Name] = out
            mu.Unlock()
        }(s)
    }

    done := make(chan struct{})
    go func() { wg.Wait(); close(done) }()

    select {
    case <-done:
    case <-ctx.Done():
    }

    return results
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/routing/ -run TestSignalEngine -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/routing/signal.go internal/routing/signal_test.go
git commit -m "feat(routing): add Signal interface and parallel SignalEngine"
```

---

### Task 2: In-Process Signals (Keyword, Context-Length, Language, Structure, PII, Conversation, Jailbreak, Modality, Reask, Event, AuthZ, Fact-Check, User-Feedback)

**Files:**
- Create: `internal/routing/signal_keyword.go`, `signal_context_length.go`, `signal_language.go`, `signal_structure.go`, `signal_pii.go`, `signal_conversation.go`, `signal_jailbreak.go`, `signal_modality.go`, `signal_reask.go`, `signal_event.go`, `signal_authz.go`, `signal_factcheck.go`, `signal_user_feedback.go`
- Test: `internal/routing/signal_keyword_test.go`, `signal_context_length_test.go`, `signal_language_test.go`, `signal_pii_test.go`
- Remove: `internal/routing/classifier.go` (logic moves to `signal_keyword.go`)

**Interfaces:**
- Consumes: `Signal` interface (Task 1), `Message` type
- Produces: 13 signal implementations, each satisfying `Signal` interface

- [ ] **Step 1: Write tests for keyword signal (refactored)**

```go
// internal/routing/signal_keyword_test.go
package routing

import (
    "context"
    "testing"
)

func TestKeywordSignal_ORMatch(t *testing.T) {
    sig := &KeywordSignal_{cfg: KeywordSignalConfig{
        SignalName: "code_task",
        Keywords:   []string{"code", "debug", "implement"},
        Operator:   "OR",
    }}
    out := sig.Evaluate(context.Background(), []Message{{Role: "user", Content: "please debug this"}})
    if !out.Fired {
        t.Error("expected keyword signal to fire")
    }
}

func TestKeywordSignal_ANDNoMatch(t *testing.T) {
    sig := &KeywordSignal_{cfg: KeywordSignalConfig{
        SignalName: "both",
        Keywords:   []string{"code", "python"},
        Operator:   "AND",
    }}
    out := sig.Evaluate(context.Background(), []Message{{Role: "user", Content: "write code"}})
    if out.Fired {
        t.Error("AND requires all keywords present")
    }
}
```

- [ ] **Step 2: Implement all 13 in-process signals**

Each signal follows the same pattern — implements `Signal` interface, extracts last user message, applies heuristic. Key implementations:

```go
// internal/routing/signal_keyword.go
package routing

import (
    "context"
    "strings"
)

type KeywordSignalConfig struct {
    SignalName string
    Keywords   []string
    Operator   string // OR (default) | AND
}

type KeywordSignal_ struct {
    cfg KeywordSignalConfig
}

func (s *KeywordSignal_) Name() string { return s.cfg.SignalName }

func (s *KeywordSignal_) Evaluate(_ context.Context, msgs []Message) *SignalOutput {
    text := lastUserContent(msgs)
    if text == "" {
        return &SignalOutput{Name: s.cfg.SignalName, Fired: false}
    }
    lower := strings.ToLower(text)
    fired := matchKeywords(lower, s.cfg.Keywords, s.cfg.Operator)
    conf := 0.0
    if fired {
        conf = 1.0
    }
    return &SignalOutput{Name: s.cfg.SignalName, Fired: fired, Confidence: conf}
}

func lastUserContent(msgs []Message) string {
    for i := len(msgs) - 1; i >= 0; i-- {
        if msgs[i].Role == "user" {
            return msgs[i].Content
        }
    }
    return ""
}

func matchKeywords(text string, keywords []string, op string) bool {
    if strings.ToUpper(op) == "AND" {
        for _, kw := range keywords {
            if !strings.Contains(text, strings.ToLower(kw)) {
                return false
            }
        }
        return len(keywords) > 0
    }
    for _, kw := range keywords {
        if strings.Contains(text, strings.ToLower(kw)) {
            return true
        }
    }
    return false
}
```

```go
// internal/routing/signal_context_length.go
package routing

import "context"

type ContextLengthSignal struct {
    Thresholds []int // e.g. [4096, 32768] → "short", "medium", "long"
}

func (s *ContextLengthSignal) Name() string { return "context_length" }

func (s *ContextLengthSignal) Evaluate(_ context.Context, msgs []Message) *SignalOutput {
    totalChars := 0
    for _, m := range msgs {
        totalChars += len(m.Content)
    }
    // Approximate tokens as chars/4
    tokens := totalChars / 4
    value := "short"
    for i, thresh := range s.Thresholds {
        if tokens >= thresh {
            switch i {
            case 0:
                value = "medium"
            default:
                value = "long"
            }
        }
    }
    return &SignalOutput{Name: "context_length", Fired: true, Confidence: 1.0, Value: value}
}
```

```go
// internal/routing/signal_language.go
package routing

import (
    "context"
    "unicode"
)

type LanguageSignal struct{}

func (s *LanguageSignal) Name() string { return "language" }

func (s *LanguageSignal) Evaluate(_ context.Context, msgs []Message) *SignalOutput {
    text := lastUserContent(msgs)
    lang := detectLanguage(text)
    return &SignalOutput{Name: "language", Fired: true, Confidence: 0.8, Value: lang}
}

func detectLanguage(text string) string {
    cjk, latin, cyrillic := 0, 0, 0
    for _, r := range text {
        if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) {
            cjk++
        } else if unicode.Is(unicode.Latin, r) {
            latin++
        } else if unicode.Is(unicode.Cyrillic, r) {
            cyrillic++
        }
    }
    if cjk > latin && cjk > cyrillic {
        return "cjk"
    }
    if cyrillic > latin {
        return "cyrillic"
    }
    return "latin"
}
```

```go
// internal/routing/signal_pii.go
package routing

import (
    "context"
    "regexp"
)

type PIISignal struct{}

func (s *PIISignal) Name() string { return "pii" }

var piiPatterns = []*regexp.Regexp{
    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),           // SSN
    regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), // Credit card
    regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), // Email
}

func (s *PIISignal) Evaluate(_ context.Context, msgs []Message) *SignalOutput {
    text := lastUserContent(msgs)
    for _, pat := range piiPatterns {
        if pat.MatchString(text) {
            return &SignalOutput{Name: "pii", Fired: true, Confidence: 0.9}
        }
    }
    return &SignalOutput{Name: "pii", Fired: false}
}
```

```go
// internal/routing/signal_conversation.go
package routing

import "context"

type ConversationSignal struct{}

func (s *ConversationSignal) Name() string { return "conversation" }

func (s *ConversationSignal) Evaluate(_ context.Context, msgs []Message) *SignalOutput {
    userMsgs, toolMsgs := 0, 0
    for _, m := range msgs {
        switch m.Role {
        case "user":
            userMsgs++
        case "tool":
            toolMsgs++
        }
    }
    value := "single_turn"
    if userMsgs > 3 || toolMsgs > 2 {
        value = "multi_turn"
    }
    if toolMsgs > 5 {
        value = "tool_heavy"
    }
    return &SignalOutput{Name: "conversation", Fired: true, Confidence: 1.0, Value: value}
}
```

(Remaining signals — `signal_structure.go`, `signal_jailbreak.go`, `signal_modality.go`, `signal_reask.go`, `signal_event.go`, `signal_authz.go`, `signal_factcheck.go`, `signal_user_feedback.go` — follow the same pattern: implement `Signal` interface, use in-process heuristics.)

- [ ] **Step 3: Run all signal tests**

Run: `go test ./internal/routing/ -run TestSignal -v`
Expected: All PASS

- [ ] **Step 4: Remove old classifier.go**

```bash
git rm internal/routing/classifier.go
```

- [ ] **Step 5: Commit**

```bash
git add internal/routing/signal*.go
git commit -m "feat(routing): add 13 in-process signal evaluators"
```

---

### Task 3: Embedding Client and Embedding Signal

**Files:**
- Create: `internal/routing/embedding_client.go`, `internal/routing/signal_embedding.go`
- Test: `internal/routing/embedding_client_test.go`, `internal/routing/signal_embedding_test.go`

**Interfaces:**
- Consumes: `Signal` interface (Task 1), Ollama `/api/embeddings` HTTP API
- Produces: `EmbeddingClient` (`Embed(ctx, text) ([]float64, error)`, `EmbedBatch(ctx, []string) ([][]float64, error)`), `EmbeddingSignal` (compares query embedding against prototype vectors via cosine similarity)

- [ ] **Step 1: Write failing test for EmbeddingClient**

```go
// internal/routing/embedding_client_test.go
package routing

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestEmbeddingClient_Embed(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "embedding": []float64{0.1, 0.2, 0.3, 0.4},
        })
    }))
    defer srv.Close()

    client := NewEmbeddingClient(srv.URL, "nomic-embed-text")
    vec, err := client.Embed(context.Background(), "hello world")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(vec) != 4 {
        t.Fatalf("expected 4 dims, got %d", len(vec))
    }
}
```

- [ ] **Step 2: Implement EmbeddingClient**

```go
// internal/routing/embedding_client.go
package routing

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "math"
    "net/http"
    "time"
)

type EmbeddingClient struct {
    baseURL string
    model   string
    client  *http.Client
}

func NewEmbeddingClient(baseURL, model string) *EmbeddingClient {
    return &EmbeddingClient{
        baseURL: baseURL,
        model:   model,
        client:  &http.Client{Timeout: 10 * time.Second},
    }
}

func (c *EmbeddingClient) Embed(ctx context.Context, text string) ([]float64, error) {
    body, _ := json.Marshal(map[string]string{"model": c.model, "prompt": text})
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/embeddings", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
        return nil, fmt.Errorf("embedding API %d: %s", resp.StatusCode, b)
    }
    var result struct {
        Embedding []float64 `json:"embedding"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    return result.Embedding, nil
}

// CosineSimilarity computes cosine similarity between two vectors.
func CosineSimilarity(a, b []float64) float64 {
    if len(a) != len(b) || len(a) == 0 {
        return 0
    }
    var dot, normA, normB float64
    for i := range a {
        dot += a[i] * b[i]
        normA += a[i] * a[i]
        normB += b[i] * b[i]
    }
    denom := math.Sqrt(normA) * math.Sqrt(normB)
    if denom == 0 {
        return 0
    }
    return dot / denom
}
```

- [ ] **Step 3: Implement EmbeddingSignal**

```go
// internal/routing/signal_embedding.go
package routing

import "context"

type EmbeddingSignalConfig struct {
    SignalName  string
    Threshold  float64    // minimum similarity to fire (e.g. 0.75)
    Prototypes []string   // candidate phrases to embed and compare against
}

type EmbeddingSignal struct {
    cfg        EmbeddingSignalConfig
    client     *EmbeddingClient
    protoVecs  [][]float64  // pre-computed prototype embeddings
    ready      bool
}

func NewEmbeddingSignal(cfg EmbeddingSignalConfig, client *EmbeddingClient) *EmbeddingSignal {
    return &EmbeddingSignal{cfg: cfg, client: client}
}

func (s *EmbeddingSignal) Name() string { return s.cfg.SignalName }

func (s *EmbeddingSignal) Init(ctx context.Context) error {
    s.protoVecs = make([][]float64, len(s.cfg.Prototypes))
    for i, p := range s.cfg.Prototypes {
        vec, err := s.client.Embed(ctx, p)
        if err != nil {
            return err
        }
        s.protoVecs[i] = vec
    }
    s.ready = true
    return nil
}

func (s *EmbeddingSignal) Evaluate(ctx context.Context, msgs []Message) *SignalOutput {
    if !s.ready || s.client == nil {
        return &SignalOutput{Name: s.cfg.SignalName, Fired: false}
    }
    text := lastUserContent(msgs)
    if text == "" {
        return &SignalOutput{Name: s.cfg.SignalName, Fired: false}
    }
    queryVec, err := s.client.Embed(ctx, text)
    if err != nil {
        return &SignalOutput{Name: s.cfg.SignalName, Fired: false}
    }
    maxSim := 0.0
    for _, pv := range s.protoVecs {
        sim := CosineSimilarity(queryVec, pv)
        if sim > maxSim {
            maxSim = sim
        }
    }
    fired := maxSim >= s.cfg.Threshold
    return &SignalOutput{Name: s.cfg.SignalName, Fired: fired, Confidence: maxSim}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/routing/ -run TestEmbedding -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/routing/embedding_client.go internal/routing/signal_embedding.go internal/routing/embedding_client_test.go internal/routing/signal_embedding_test.go
git commit -m "feat(routing): add Ollama embedding client and embedding signal"
```

---

### Task 4: LLM Classifier (Domain + Complexity Signals)

**Files:**
- Create: `internal/routing/llm_classifier.go`, `internal/routing/signal_domain.go`, `internal/routing/signal_complexity.go`
- Test: `internal/routing/signal_domain_test.go`, `internal/routing/signal_complexity_test.go`

**Interfaces:**
- Consumes: `Signal` interface (Task 1), Ollama/LLM chat completion API
- Produces: `LLMClassifier` (`Classify(ctx, prompt, categories) (string, float64, error)`), `DomainSignal`, `ComplexitySignal`

The LLM classifier uses the same Ollama endpoint (or any OpenAI-compatible endpoint) that the LLM Judge uses. It sends a single structured prompt asking for classification and parses the JSON response.

- [ ] **Step 1: Implement LLMClassifier**

```go
// internal/routing/llm_classifier.go
package routing

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

type LLMClassifier struct {
    baseURL string
    model   string
    client  *http.Client
}

func NewLLMClassifier(baseURL, model string) *LLMClassifier {
    return &LLMClassifier{
        baseURL: baseURL,
        model:   model,
        client:  &http.Client{Timeout: 30 * time.Second},
    }
}

func (c *LLMClassifier) Classify(ctx context.Context, text string, categories []string) (string, float64, error) {
    prompt := fmt.Sprintf(
        "Classify the following text into exactly one category. Respond with ONLY a JSON object: {\"category\": \"<choice>\", \"confidence\": <0.0-1.0>}\n\nCategories: %v\n\nText: %s",
        categories, text,
    )
    body, _ := json.Marshal(map[string]interface{}{
        "model": c.model,
        "messages": []map[string]string{
            {"role": "user", "content": prompt},
        },
        "temperature": 0.0,
    })
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
    if err != nil {
        return "", 0, err
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.client.Do(req)
    if err != nil {
        return "", 0, err
    }
    defer resp.Body.Close()
    respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
    var chatResp struct {
        Choices []struct {
            Message struct {
                Content string `json:"content"`
            } `json:"message"`
        } `json:"choices"`
    }
    if err := json.Unmarshal(respBody, &chatResp); err != nil {
        return "", 0, err
    }
    if len(chatResp.Choices) == 0 {
        return "", 0, fmt.Errorf("no choices in LLM response")
    }
    var result struct {
        Category   string  `json:"category"`
        Confidence float64 `json:"confidence"`
    }
    if err := json.Unmarshal([]byte(chatResp.Choices[0].Message.Content), &result); err != nil {
        return chatResp.Choices[0].Message.Content, 0.5, nil
    }
    return result.Category, result.Confidence, nil
}
```

- [ ] **Step 2: Implement Domain and Complexity signals using LLMClassifier**

```go
// internal/routing/signal_domain.go
package routing

import "context"

var defaultDomains = []string{"code", "business", "science", "creative", "math", "general"}

type DomainSignal struct {
    classifier *LLMClassifier
    domains    []string
}

func NewDomainSignal(classifier *LLMClassifier, domains []string) *DomainSignal {
    if len(domains) == 0 {
        domains = defaultDomains
    }
    return &DomainSignal{classifier: classifier, domains: domains}
}

func (s *DomainSignal) Name() string { return "domain" }

func (s *DomainSignal) Evaluate(ctx context.Context, msgs []Message) *SignalOutput {
    text := lastUserContent(msgs)
    if text == "" || s.classifier == nil {
        return &SignalOutput{Name: "domain", Fired: false}
    }
    category, confidence, err := s.classifier.Classify(ctx, text, s.domains)
    if err != nil {
        return &SignalOutput{Name: "domain", Fired: false}
    }
    return &SignalOutput{Name: "domain", Fired: true, Confidence: confidence, Value: category}
}
```

```go
// internal/routing/signal_complexity.go
package routing

import (
    "context"
    "strconv"
)

type ComplexitySignal struct {
    classifier *LLMClassifier
}

func NewComplexitySignal(classifier *LLMClassifier) *ComplexitySignal {
    return &ComplexitySignal{classifier: classifier}
}

func (s *ComplexitySignal) Name() string { return "complexity" }

func (s *ComplexitySignal) Evaluate(ctx context.Context, msgs []Message) *SignalOutput {
    text := lastUserContent(msgs)
    if text == "" || s.classifier == nil {
        return &SignalOutput{Name: "complexity", Fired: false}
    }
    level, confidence, err := s.classifier.Classify(ctx, text, []string{"1", "2", "3", "4", "5"})
    if err != nil {
        return &SignalOutput{Name: "complexity", Fired: false}
    }
    score, _ := strconv.Atoi(level)
    fired := score >= 3
    return &SignalOutput{Name: "complexity", Fired: fired, Confidence: confidence, Value: level}
}
```

- [ ] **Step 3: Write tests with mock LLM server**
- [ ] **Step 4: Run tests**

Run: `go test ./internal/routing/ -run "TestDomain|TestComplexity" -v`

- [ ] **Step 5: Commit**

```bash
git add internal/routing/llm_classifier.go internal/routing/signal_domain.go internal/routing/signal_complexity.go internal/routing/signal_domain_test.go internal/routing/signal_complexity_test.go
git commit -m "feat(routing): add LLM-based domain and complexity signals"
```

---

### Task 5: Boolean Expression Decision Tree

**Files:**
- Create: `internal/routing/decision_tree.go`
- Test: `internal/routing/decision_tree_test.go`
- Remove: `internal/routing/decision.go` (replaced)

**Interfaces:**
- Consumes: `SignalOutput` map from `SignalEngine`
- Produces: `DecisionTree` struct, `EvaluateDecisions(signals, rules) *DecisionResult` with `DecisionResult{DecisionName, ModelRefs, Confidence, Algorithm}`

The new decision engine supports nested AND/OR/NOT boolean expressions (replacing the flat condition list), tiered priority, and confidence-based selection.

- [ ] **Step 1: Write failing test for nested boolean logic**

```go
// internal/routing/decision_tree_test.go
package routing

import "testing"

func TestDecisionTree_ANDNested(t *testing.T) {
    signals := map[string]*SignalOutput{
        "code_task":    {Name: "code_task", Fired: true, Confidence: 1.0},
        "complexity":   {Name: "complexity", Fired: true, Confidence: 0.9, Value: "4"},
    }
    rules := []DecisionRuleV2{
        {
            Name:     "hard_code",
            Priority: 100,
            Condition: &ConditionNode{
                Op: "AND",
                Children: []*ConditionNode{
                    {Signal: "code_task"},
                    {Signal: "complexity", MinConfidence: 0.8},
                },
            },
            ModelRefs: []string{"reasoning"},
            Algorithm: "static",
        },
    }
    result := EvaluateDecisions(signals, rules)
    if result == nil || result.DecisionName != "hard_code" {
        t.Fatalf("expected 'hard_code', got %v", result)
    }
}

func TestDecisionTree_NOTBlocksMatch(t *testing.T) {
    signals := map[string]*SignalOutput{
        "code_task": {Name: "code_task", Fired: true, Confidence: 1.0},
        "jailbreak": {Name: "jailbreak", Fired: true, Confidence: 0.95},
    }
    rules := []DecisionRuleV2{
        {
            Name:     "safe_code",
            Priority: 100,
            Condition: &ConditionNode{
                Op: "AND",
                Children: []*ConditionNode{
                    {Signal: "code_task"},
                    {Op: "NOT", Children: []*ConditionNode{{Signal: "jailbreak"}}},
                },
            },
            ModelRefs: []string{"code"},
            Algorithm: "static",
        },
    }
    result := EvaluateDecisions(signals, rules)
    if result != nil {
        t.Fatalf("expected nil (NOT blocks match), got %v", result.DecisionName)
    }
}
```

- [ ] **Step 2: Implement decision tree with AND/OR/NOT**

```go
// internal/routing/decision_tree.go
package routing

import "sort"

type ConditionNode struct {
    Op            string           // AND | OR | NOT | "" (leaf)
    Signal        string           // leaf: signal name to check
    MinConfidence float64          // leaf: minimum confidence to count as fired
    Value         string           // leaf: optional value match (e.g. domain == "code")
    Children      []*ConditionNode // branch nodes
}

type DecisionRuleV2 struct {
    Name      string
    Priority  int
    Tier      int            // lower tier wins first (0 = default)
    Condition *ConditionNode // nil = unconditional (fallback)
    ModelRefs []string
    Algorithm string
}

type DecisionResultV2 struct {
    DecisionName string
    ModelRefs    []string
    Confidence   float64
    Algorithm    string
}

func EvaluateDecisions(signals map[string]*SignalOutput, rules []DecisionRuleV2) *DecisionResultV2 {
    sorted := make([]DecisionRuleV2, len(rules))
    copy(sorted, rules)
    sort.Slice(sorted, func(i, j int) bool {
        if sorted[i].Tier != sorted[j].Tier {
            return sorted[i].Tier < sorted[j].Tier
        }
        return sorted[i].Priority > sorted[j].Priority
    })

    for _, rule := range sorted {
        if rule.Condition == nil {
            return &DecisionResultV2{
                DecisionName: rule.Name,
                ModelRefs:    rule.ModelRefs,
                Confidence:   1.0,
                Algorithm:    rule.Algorithm,
            }
        }
        fired, conf := evaluateNode(rule.Condition, signals)
        if fired {
            return &DecisionResultV2{
                DecisionName: rule.Name,
                ModelRefs:    rule.ModelRefs,
                Confidence:   conf,
                Algorithm:    rule.Algorithm,
            }
        }
    }
    return nil
}

func evaluateNode(node *ConditionNode, signals map[string]*SignalOutput) (bool, float64) {
    if node == nil {
        return true, 1.0
    }

    // Leaf node
    if node.Op == "" && node.Signal != "" {
        sig, ok := signals[node.Signal]
        if !ok || !sig.Fired {
            return false, 0
        }
        if node.MinConfidence > 0 && sig.Confidence < node.MinConfidence {
            return false, 0
        }
        if node.Value != "" && sig.Value != node.Value {
            return false, 0
        }
        return true, sig.Confidence
    }

    switch node.Op {
    case "AND":
        totalConf := 0.0
        for _, child := range node.Children {
            fired, conf := evaluateNode(child, signals)
            if !fired {
                return false, 0
            }
            totalConf += conf
        }
        if len(node.Children) == 0 {
            return true, 1.0
        }
        return true, totalConf / float64(len(node.Children))

    case "OR":
        maxConf := 0.0
        for _, child := range node.Children {
            fired, conf := evaluateNode(child, signals)
            if fired && conf > maxConf {
                maxConf = conf
            }
        }
        return maxConf > 0, maxConf

    case "NOT":
        if len(node.Children) == 0 {
            return true, 1.0
        }
        fired, _ := evaluateNode(node.Children[0], signals)
        if fired {
            return false, 0
        }
        return true, 1.0
    }

    return false, 0
}
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Remove old decision.go**
- [ ] **Step 5: Commit**

---

### Task 6: Selector Interface and Registry

**Files:**
- Create: `internal/routing/selector.go`
- Test: `internal/routing/selector_test.go`

**Interfaces:**
- Consumes: `DecisionResultV2` (Task 5), `ResolvedProvider` (existing)
- Produces: `Selector` interface (`Select(ctx, SelectionContext) *SelectionResult`), `SelectorRegistry` (name→Selector map), `SelectionContext` struct (candidates, signals, history)

```go
// internal/routing/selector.go
package routing

import "context"

type SelectionContext struct {
    Candidates []string                  // model_refs from decision
    Signals    map[string]*SignalOutput   // all evaluated signals
    Messages   []Message                 // original request messages
    SessionID  string                    // for session-aware routing
    UserID     string                    // for personalization
}

type SelectionResult struct {
    BackendName string
    Confidence  float64
    Reason      string
}

type Selector interface {
    Name() string
    Select(ctx context.Context, sc *SelectionContext) *SelectionResult
}

type SelectorRegistry struct {
    selectors map[string]Selector
}

func NewSelectorRegistry() *SelectorRegistry {
    return &SelectorRegistry{selectors: make(map[string]Selector)}
}

func (r *SelectorRegistry) Register(s Selector) {
    r.selectors[s.Name()] = s
}

func (r *SelectorRegistry) Get(name string) Selector {
    return r.selectors[name]
}
```

- [ ] **Step 1-5: Write test, implement, verify, commit**

---

### Task 7: Core Selection Algorithms (Static, Elo, KNN, Latency-Aware, Multi-Factor, Session-Aware)

**Files:**
- Create: `selector_static.go`, `selector_elo.go`, `selector_knn.go`, `selector_latency.go`, `selector_multifactor.go`, `selector_session.go`
- Test: `selector_elo_test.go`, `selector_knn_test.go`, `selector_latency_test.go`

These are pure-Go algorithms that don't require external ML. Elo and KNN need persistent state (Task 9 provides SQLite store; until then, they use in-memory state).

**Key algorithm implementations:**

- **Static**: picks first candidate (existing behavior)
- **Elo**: maintains Bradley-Terry ratings per model per domain, picks highest-rated for matching domain
- **KNN**: embeds query (via embedding client), finds K nearest stored queries, weighted vote on which model performed best
- **Latency-Aware**: tracks p90 TTFT per model in a sliding window, picks fastest meeting quality threshold
- **Multi-Factor**: weighted score = 0.4×quality + 0.2×latency + 0.2×cost + 0.2×load
- **Session-Aware**: wraps any inner selector, returns same model for same session_id within TTL

---

### Task 8: Advanced Selection Algorithms (Router-DC, AutoMix, Hybrid, RL-Driven)

**Files:**
- Create: `selector_routerdc.go`, `selector_automix.go`, `selector_hybrid.go`, `selector_rl.go`
- Test: `selector_routerdc_test.go`, `selector_automix_test.go`

- **Router-DC**: embeds query via Ollama, embeds each candidate model's capability description, picks highest cosine similarity
- **AutoMix**: sends to cheapest model, asks LLM Judge "does this fully answer the question?", escalates if no
- **Hybrid**: runs Elo + Router-DC + Multi-Factor in parallel, blends scores with configurable weights
- **RL-Driven**: Thompson Sampling on per-model Beta(α,β) distributions, updated from feedback

---

### Task 9: Stub Algorithms (SVM, MLP, GMTRouter)

**Files:**
- Create: `selector_svm.go`, `selector_mlp.go`, `selector_gmt.go`

These return `nil` (graceful fallback to next selector) with a log message explaining they require training data. They exist so the config parser doesn't reject `algorithm: svm` — it just falls through.

---

### Task 10: State Store (SQLite)

**Files:**
- Create: `internal/routing/state.go`
- Test: `internal/routing/state_test.go`

**Interfaces:**
- Produces: `StateStore` with methods for Elo scores (`GetElo`, `UpdateElo`), KNN history (`StoreQuery`, `FindNearest`), RL betas (`GetBeta`, `UpdateBeta`), latency records (`RecordLatency`, `GetP90`)

Uses a separate SQLite file (`~/.defenseclaw/routing_state.db`) to avoid contending with audit.db.

---

### Task 11: Metrics and Latency Tracker

**Files:**
- Create: `internal/routing/metrics.go`

Tracks per-model: request count, p50/p90/p99 latency, error rate, token usage. Fed by a callback after each upstream response completes. Used by Latency-Aware and Multi-Factor selectors.

---

### Task 12: Refactor Router to Use New Engine

**Files:**
- Modify: `internal/routing/router.go`
- Modify: `internal/routing/config.go`
- Modify: `internal/config/config.go`
- Modify: `internal/gateway/model_router_adapter.go`

Refactor `SemanticRouter` to compose: `SignalEngine` → `EvaluateDecisions` → `SelectorRegistry.Get(algorithm).Select()`. Update config types to support the full schema (embedding config, LLM classifier config, signal enable/disable, decision tree schema, algorithm parameters).

Maintains backward compatibility: old configs with flat `conditions: [{type: keyword, name: x}]` are auto-translated to `ConditionNode{Op: "AND", Children: [...]}` at parse time.

---

### Task 13: Integration Test — Full Pipeline

**Files:**
- Create: `internal/routing/integration_test.go`

End-to-end test: load a full YAML config → construct router → send test messages → assert correct routing decisions for each algorithm. Uses httptest mock for Ollama.

---

### Task 14: Documentation

**Files:**
- Modify: `docs/ROUTING.md`

Update with full config reference for all 14 algorithms, 17 signals, decision tree syntax, and examples.

---

## Dependency Graph

```
Task 1 (Signal interface)
   ├── Task 2 (13 in-process signals)
   ├── Task 3 (Embedding client + signal)
   │      └── Task 8 (Router-DC, KNN needs embeddings)
   └── Task 4 (LLM classifier + signals)
          └── Task 8 (AutoMix needs LLM verification)

Task 5 (Decision tree)
   └── Task 12 (Router refactor)

Task 6 (Selector interface)
   ├── Task 7 (6 core algorithms)
   ├── Task 8 (4 advanced algorithms)
   └── Task 9 (3 stubs)

Task 10 (State store)
   └── Task 7 (Elo, KNN persistence)

Task 11 (Metrics)
   └── Task 7 (Latency-Aware)

Task 12 (Router refactor) ← depends on Tasks 1-11
   └── Task 13 (Integration test)
       └── Task 14 (Documentation)
```

## Estimated Timeline

| Week | Tasks | Deliverable |
|------|-------|-------------|
| 1 | Tasks 1-4 | Signal engine + all 17 signals working |
| 2 | Tasks 5-9 | Decision tree + all 14 selectors registered |
| 3 | Tasks 10-14 | State persistence, router refactor, integration tests, docs |
