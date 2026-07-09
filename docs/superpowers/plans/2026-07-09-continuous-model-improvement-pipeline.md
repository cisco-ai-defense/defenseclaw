# Continuous Model Improvement Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an automated pipeline where DefenseClaw captures LLM request traces, trains local models per category using Unsloth or mlx-lm-lora, evaluates them against frontier, and promotes to production when quality threshold is met.

**Architecture:** DefenseClaw gateway captures every LLM request's prompt + response + SR classification into a SQLite store (async, non-blocking). A trigger mechanism (auto or manual) fires the training pipeline: extract → dataset → train (subprocess) → export GGUF → deploy to llama-server → evaluate via LLM-as-judge → promote if passes. Post-promotion quality monitoring auto-rollbacks if quality degrades.

**Tech Stack:** Go (gateway + pipeline orchestration), Python (training subprocess — Unsloth or mlx-lm-lora), SQLite (trace store via `modernc.org/sqlite` already in go.mod), llama.cpp (model hosting), vLLM-SR (classification, already integrated).

## Global Constraints

- Branch: `feature/semantic-router-interface`
- SQLite driver: `modernc.org/sqlite` (already in go.mod, pure Go, no CGo)
- Training subprocess: Python (Unsloth or mlx-lm-lora), executed via `exec.Command`
- Trace capture: MUST be async, non-blocking, never impact response latency
- All state files under `~/.defenseclaw/` (models/, training/, training-store.db)
- Tests: `go test ./internal/training/ -v -count=1`
- Build check: `go build ./...` must pass after every task
- No new Go dependencies beyond what's already in go.mod (SQLite driver exists)
- Config types mirror existing pattern in `internal/config/config.go`

---

### Task 1: Config Types + Training Store Schema

**Files:**
- Create: `internal/config/training.go`
- Create: `internal/training/store.go`
- Create: `internal/training/store_test.go`

**Interfaces:**
- Consumes: Nothing (foundational)
- Produces:
  - `config.TrainingConfig` struct with all fields from spec
  - `training.Store` struct with `New(dbPath) (*Store, error)`, `CaptureTrace(entry TraceEntry) error`, `CountByCategory(category string) (int, error)`, `ExtractForTraining(category string, limit int) ([]TraceEntry, error)`, `MarkUsed(ids []int64, runID string) error`
  - `training.TraceEntry` struct: `{ID, Timestamp, Category, RecommendedModel, Prompt, Response, ModelUsed, IsPromotedModel, LatencyMs, TokensIn, TokensOut, UsedForTraining, TrainingRunID}`

- [ ] **Step 1: Write failing test for Store**

```go
// internal/training/store_test.go
package training

import (
    "path/filepath"
    "testing"
)

func TestStore_CaptureAndCount(t *testing.T) {
    dbPath := filepath.Join(t.TempDir(), "test.db")
    store, err := NewStore(dbPath)
    if err != nil {
        t.Fatalf("NewStore: %v", err)
    }
    defer store.Close()

    entry := TraceEntry{
        Category:         "code",
        RecommendedModel: "reasoning",
        Prompt:           `[{"role":"user","content":"implement quicksort"}]`,
        Response:         "def quicksort(arr)...",
        ModelUsed:        "claude-sonnet-4-6",
        LatencyMs:        450,
        TokensIn:         50,
        TokensOut:        200,
    }

    if err := store.CaptureTrace(entry); err != nil {
        t.Fatalf("CaptureTrace: %v", err)
    }

    count, err := store.CountByCategory("code")
    if err != nil {
        t.Fatalf("CountByCategory: %v", err)
    }
    if count != 1 {
        t.Fatalf("expected count 1, got %d", count)
    }

    count2, _ := store.CountByCategory("reasoning")
    if count2 != 0 {
        t.Fatalf("expected count 0 for reasoning, got %d", count2)
    }
}

func TestStore_ExtractAndMarkUsed(t *testing.T) {
    dbPath := filepath.Join(t.TempDir(), "test.db")
    store, _ := NewStore(dbPath)
    defer store.Close()

    for i := 0; i < 10; i++ {
        store.CaptureTrace(TraceEntry{
            Category: "code",
            Prompt:   "prompt",
            Response: "response",
            ModelUsed: "frontier",
        })
    }

    traces, err := store.ExtractForTraining("code", 5)
    if err != nil {
        t.Fatalf("ExtractForTraining: %v", err)
    }
    if len(traces) != 5 {
        t.Fatalf("expected 5 traces, got %d", len(traces))
    }

    ids := make([]int64, len(traces))
    for i, tr := range traces {
        ids[i] = tr.ID
    }
    if err := store.MarkUsed(ids, "run-001"); err != nil {
        t.Fatalf("MarkUsed: %v", err)
    }

    // After marking, count of unused should be 5
    remaining, _ := store.CountByCategory("code")
    if remaining != 5 {
        t.Fatalf("expected 5 remaining, got %d", remaining)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/training/ -run "TestStore" -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement Store + TraceEntry + Config types**

```go
// internal/training/store.go
package training

import (
    "database/sql"
    "fmt"
    "time"

    _ "modernc.org/sqlite"
)

type TraceEntry struct {
    ID               int64
    Timestamp        string
    Category         string
    RecommendedModel string
    Prompt           string
    Response         string
    ModelUsed        string
    IsPromotedModel  bool
    LatencyMs        int64
    TokensIn         int
    TokensOut        int
    UsedForTraining  bool
    TrainingRunID    string
}

type Store struct {
    db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, fmt.Errorf("training store: open: %w", err)
    }
    if err := initSchema(db); err != nil {
        db.Close()
        return nil, err
    }
    return &Store{db: db}, nil
}

func initSchema(db *sql.DB) error {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS training_traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            category TEXT NOT NULL,
            recommended_model TEXT DEFAULT '',
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            model_used TEXT NOT NULL,
            is_promoted_model BOOLEAN DEFAULT FALSE,
            latency_ms INTEGER DEFAULT 0,
            tokens_in INTEGER DEFAULT 0,
            tokens_out INTEGER DEFAULT 0,
            used_for_training BOOLEAN DEFAULT FALSE,
            training_run_id TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_category_unused ON training_traces(category, used_for_training);
    `)
    return err
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CaptureTrace(e TraceEntry) error {
    _, err := s.db.Exec(`
        INSERT INTO training_traces (category, recommended_model, prompt, response, model_used, is_promoted_model, latency_ms, tokens_in, tokens_out)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        e.Category, e.RecommendedModel, e.Prompt, e.Response, e.ModelUsed, e.IsPromotedModel, e.LatencyMs, e.TokensIn, e.TokensOut)
    return err
}

func (s *Store) CountByCategory(category string) (int, error) {
    var count int
    err := s.db.QueryRow(`SELECT COUNT(*) FROM training_traces WHERE category = ? AND used_for_training = FALSE`, category).Scan(&count)
    return count, err
}

func (s *Store) ExtractForTraining(category string, limit int) ([]TraceEntry, error) {
    rows, err := s.db.Query(`
        SELECT id, timestamp, category, recommended_model, prompt, response, model_used, is_promoted_model, latency_ms, tokens_in, tokens_out
        FROM training_traces
        WHERE category = ? AND used_for_training = FALSE
        ORDER BY timestamp DESC
        LIMIT ?`, category, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var traces []TraceEntry
    for rows.Next() {
        var e TraceEntry
        if err := rows.Scan(&e.ID, &e.Timestamp, &e.Category, &e.RecommendedModel, &e.Prompt, &e.Response, &e.ModelUsed, &e.IsPromotedModel, &e.LatencyMs, &e.TokensIn, &e.TokensOut); err != nil {
            return nil, err
        }
        traces = append(traces, e)
    }
    return traces, rows.Err()
}

func (s *Store) MarkUsed(ids []int64, runID string) error {
    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    stmt, err := tx.Prepare(`UPDATE training_traces SET used_for_training = TRUE, training_run_id = ? WHERE id = ?`)
    if err != nil {
        tx.Rollback()
        return err
    }
    defer stmt.Close()
    for _, id := range ids {
        if _, err := stmt.Exec(runID, id); err != nil {
            tx.Rollback()
            return err
        }
    }
    return tx.Commit()
}
```

```go
// internal/config/training.go
package config

// TrainingConfig holds the continuous model improvement pipeline configuration.
type TrainingConfig struct {
    Enabled              bool                    `mapstructure:"enabled"                yaml:"enabled"`
    Backend              string                  `mapstructure:"backend"                yaml:"backend,omitempty"`
    ModelsDir            string                  `mapstructure:"models_dir"             yaml:"models_dir,omitempty"`
    LlamaServerPort      int                     `mapstructure:"llama_server_port"      yaml:"llama_server_port,omitempty"`
    TrainingTimeoutHours int                     `mapstructure:"training_timeout_hours" yaml:"training_timeout_hours,omitempty"`
    TraceRetentionDays   int                     `mapstructure:"trace_retention_days"   yaml:"trace_retention_days,omitempty"`
    BaseModels           []TrainingBaseModel     `mapstructure:"base_models"            yaml:"base_models,omitempty"`
    Categories           []TrainingCategory      `mapstructure:"categories"             yaml:"categories,omitempty"`
}

type TrainingBaseModel struct {
    ID      string `mapstructure:"id"       yaml:"id"`
    HFRepo  string `mapstructure:"hf_repo"  yaml:"hf_repo,omitempty"`
    MLXRepo string `mapstructure:"mlx_repo" yaml:"mlx_repo,omitempty"`
    Size    string `mapstructure:"size"     yaml:"size,omitempty"`
}

type TrainingCategory struct {
    Name            string  `mapstructure:"name"              yaml:"name"`
    BaseModel       string  `mapstructure:"base_model"        yaml:"base_model"`
    Algorithm       string  `mapstructure:"algorithm"         yaml:"algorithm,omitempty"`
    MinTraces       int     `mapstructure:"min_traces"        yaml:"min_traces,omitempty"`
    EvalThreshold   float64 `mapstructure:"eval_threshold"    yaml:"eval_threshold,omitempty"`
    EvalPrompts     int     `mapstructure:"eval_prompts"      yaml:"eval_prompts,omitempty"`
    AutoTrigger     bool    `mapstructure:"auto_trigger"      yaml:"auto_trigger,omitempty"`
    MonitorInterval int     `mapstructure:"monitor_interval"  yaml:"monitor_interval,omitempty"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/training/ -run "TestStore" -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Verify full build**

Run: `go build ./...`
Expected: Success

- [ ] **Step 6: Commit**

```bash
git add internal/training/store.go internal/training/store_test.go internal/config/training.go
git commit -m "feat(training): add trace store (SQLite) and TrainingConfig types"
```

---

### Task 2: Trace Capture Integration (Gateway Hook)

**Files:**
- Create: `internal/training/capture.go`
- Modify: `internal/gateway/sidecar.go` (add store init + capture wiring)

**Interfaces:**
- Consumes: `training.Store` from Task 1, `classifyResponse` from `model_router_remote.go`
- Produces: `training.Capturer` struct with `NewCapturer(store *Store) *Capturer`, `Capture(entry TraceEntry)` (non-blocking, channel-based)

- [ ] **Step 1: Write failing test for Capturer**

```go
// internal/training/capture_test.go
package training

import (
    "path/filepath"
    "testing"
    "time"
)

func TestCapturer_NonBlocking(t *testing.T) {
    dbPath := filepath.Join(t.TempDir(), "test.db")
    store, _ := NewStore(dbPath)
    defer store.Close()

    cap := NewCapturer(store)
    defer cap.Stop()

    // Should not block even if we send many entries
    for i := 0; i < 200; i++ {
        cap.Capture(TraceEntry{
            Category: "code",
            Prompt:   "test prompt",
            Response: "test response",
            ModelUsed: "test-model",
        })
    }

    // Wait for async writes
    time.Sleep(100 * time.Millisecond)

    count, _ := store.CountByCategory("code")
    // At least some should have been written (channel buffer is 100)
    if count == 0 {
        t.Fatal("expected some traces to be captured")
    }
    // Might not be all 200 if channel was full (drops are acceptable)
    if count > 200 {
        t.Fatalf("impossible: got %d", count)
    }
}

func TestCapturer_Stop(t *testing.T) {
    dbPath := filepath.Join(t.TempDir(), "test.db")
    store, _ := NewStore(dbPath)
    defer store.Close()

    cap := NewCapturer(store)
    cap.Capture(TraceEntry{Category: "x", Prompt: "p", Response: "r", ModelUsed: "m"})
    cap.Stop() // should not hang

    // After stop, captures are silently dropped
    cap.Capture(TraceEntry{Category: "y", Prompt: "p", Response: "r", ModelUsed: "m"})
}
```

- [ ] **Step 2: Implement Capturer**

```go
// internal/training/capture.go
package training

import (
    "fmt"
    "os"
    "sync"
)

const captureBufferSize = 100

type Capturer struct {
    store   *Store
    ch      chan TraceEntry
    stopCh  chan struct{}
    stopped bool
    mu      sync.Mutex
}

func NewCapturer(store *Store) *Capturer {
    c := &Capturer{
        store:  store,
        ch:     make(chan TraceEntry, captureBufferSize),
        stopCh: make(chan struct{}),
    }
    go c.drain()
    return c
}

// Capture enqueues a trace entry. Non-blocking — drops if buffer is full.
func (c *Capturer) Capture(entry TraceEntry) {
    c.mu.Lock()
    if c.stopped {
        c.mu.Unlock()
        return
    }
    c.mu.Unlock()

    select {
    case c.ch <- entry:
    default:
        // Buffer full — drop silently (non-critical telemetry)
    }
}

func (c *Capturer) Stop() {
    c.mu.Lock()
    if c.stopped {
        c.mu.Unlock()
        return
    }
    c.stopped = true
    c.mu.Unlock()
    close(c.stopCh)
}

func (c *Capturer) drain() {
    for {
        select {
        case <-c.stopCh:
            // Drain remaining entries
            for {
                select {
                case entry := <-c.ch:
                    c.write(entry)
                default:
                    return
                }
            }
        case entry := <-c.ch:
            c.write(entry)
        }
    }
}

func (c *Capturer) write(entry TraceEntry) {
    if err := c.store.CaptureTrace(entry); err != nil {
        fmt.Fprintf(os.Stderr, "[training] capture write error: %v\n", err)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/training/ -run "TestCapturer" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/training/capture.go internal/training/capture_test.go
git commit -m "feat(training): add async non-blocking trace capturer"
```

---

### Task 3: Model Registry

**Files:**
- Create: `internal/training/registry.go`
- Create: `internal/training/registry_test.go`

**Interfaces:**
- Consumes: Nothing (standalone JSON file manager)
- Produces: `training.Registry` with `New(dir string) *Registry`, `RegisterVersion(category string, v ModelVersion)`, `GetPromoted(category string) *ModelVersion`, `Promote(category, versionID string)`, `Rollback(category string)`, `ListVersions(category string) []ModelVersion`

- [ ] **Step 1: Write failing test**

```go
// internal/training/registry_test.go
package training

import (
    "testing"
)

func TestRegistry_RegisterAndPromote(t *testing.T) {
    dir := t.TempDir()
    reg := NewRegistry(dir)

    v := ModelVersion{
        ID:             "code-v1",
        File:           "code-v1.gguf",
        BaseModel:      "Qwen3.5-4B",
        Algorithm:      "dpo",
        TracesUsed:     500,
        EvalScoreLocal: 8.4,
        EvalScoreFrontier: 9.1,
        EvalRatio:      0.923,
    }
    reg.RegisterVersion("code", v)

    versions := reg.ListVersions("code")
    if len(versions) != 1 {
        t.Fatalf("expected 1 version, got %d", len(versions))
    }

    // Not promoted yet
    if p := reg.GetPromoted("code"); p != nil {
        t.Fatal("should not be promoted yet")
    }

    // Promote
    reg.Promote("code", "code-v1")
    p := reg.GetPromoted("code")
    if p == nil || p.ID != "code-v1" {
        t.Fatalf("expected promoted code-v1, got %v", p)
    }

    // Rollback
    reg.Rollback("code")
    if p := reg.GetPromoted("code"); p != nil {
        t.Fatal("should be nil after rollback")
    }
}

func TestRegistry_PersistsToFile(t *testing.T) {
    dir := t.TempDir()
    reg := NewRegistry(dir)
    reg.RegisterVersion("code", ModelVersion{ID: "code-v1", File: "code-v1.gguf"})
    reg.Promote("code", "code-v1")

    // Load fresh registry from same dir
    reg2 := NewRegistry(dir)
    p := reg2.GetPromoted("code")
    if p == nil || p.ID != "code-v1" {
        t.Fatal("registry should persist across instances")
    }
}
```

- [ ] **Step 2: Implement Registry**

```go
// internal/training/registry.go
package training

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"
)

type ModelVersion struct {
    ID                string  `json:"id"`
    File              string  `json:"file"`
    BaseModel         string  `json:"base_model"`
    Algorithm         string  `json:"algorithm"`
    Created           string  `json:"created"`
    TracesUsed        int     `json:"traces_used"`
    EvalScoreLocal    float64 `json:"eval_score_local"`
    EvalScoreFrontier float64 `json:"eval_score_frontier"`
    EvalRatio         float64 `json:"eval_ratio"`
    Promoted          bool    `json:"promoted"`
    PromotedAt        string  `json:"promoted_at,omitempty"`
    RolledBack        bool    `json:"rolled_back"`
}

type categoryState struct {
    CurrentPromoted string         `json:"current_promoted"`
    Versions        []ModelVersion `json:"versions"`
}

type registryData struct {
    Categories map[string]*categoryState `json:"categories"`
}

type Registry struct {
    path string
    data registryData
    mu   sync.RWMutex
}

func NewRegistry(dir string) *Registry {
    path := filepath.Join(dir, "registry.json")
    r := &Registry{path: path, data: registryData{Categories: make(map[string]*categoryState)}}
    r.load()
    return r
}

func (r *Registry) load() {
    data, err := os.ReadFile(r.path)
    if err != nil {
        return
    }
    json.Unmarshal(data, &r.data)
    if r.data.Categories == nil {
        r.data.Categories = make(map[string]*categoryState)
    }
}

func (r *Registry) save() {
    data, _ := json.MarshalIndent(r.data, "", "  ")
    tmp := r.path + ".tmp"
    os.WriteFile(tmp, data, 0600)
    os.Rename(tmp, r.path)
}

func (r *Registry) ensureCategory(category string) *categoryState {
    if r.data.Categories[category] == nil {
        r.data.Categories[category] = &categoryState{}
    }
    return r.data.Categories[category]
}

func (r *Registry) RegisterVersion(category string, v ModelVersion) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if v.Created == "" {
        v.Created = time.Now().UTC().Format(time.RFC3339)
    }
    cs := r.ensureCategory(category)
    cs.Versions = append(cs.Versions, v)
    r.save()
}

func (r *Registry) ListVersions(category string) []ModelVersion {
    r.mu.RLock()
    defer r.mu.RUnlock()
    cs := r.data.Categories[category]
    if cs == nil {
        return nil
    }
    return cs.Versions
}

func (r *Registry) GetPromoted(category string) *ModelVersion {
    r.mu.RLock()
    defer r.mu.RUnlock()
    cs := r.data.Categories[category]
    if cs == nil || cs.CurrentPromoted == "" {
        return nil
    }
    for i := range cs.Versions {
        if cs.Versions[i].ID == cs.CurrentPromoted && cs.Versions[i].Promoted {
            return &cs.Versions[i]
        }
    }
    return nil
}

func (r *Registry) Promote(category, versionID string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    cs := r.ensureCategory(category)
    cs.CurrentPromoted = versionID
    for i := range cs.Versions {
        if cs.Versions[i].ID == versionID {
            cs.Versions[i].Promoted = true
            cs.Versions[i].PromotedAt = time.Now().UTC().Format(time.RFC3339)
        }
    }
    r.save()
}

func (r *Registry) Rollback(category string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    cs := r.data.Categories[category]
    if cs == nil {
        return
    }
    for i := range cs.Versions {
        if cs.Versions[i].ID == cs.CurrentPromoted {
            cs.Versions[i].RolledBack = true
            cs.Versions[i].Promoted = false
        }
    }
    cs.CurrentPromoted = ""
    r.save()
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/training/ -run "TestRegistry" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/training/registry.go internal/training/registry_test.go
git commit -m "feat(training): add model version registry (JSON persistence)"
```

---

### Task 4: llama-server Lifecycle Manager

**Files:**
- Create: `internal/training/llama.go`
- Create: `internal/training/llama_test.go`

**Interfaces:**
- Consumes: Nothing (standalone subprocess manager)
- Produces: `training.LlamaServer` with `NewLlamaServer(cfg LlamaConfig) *LlamaServer`, `Start(ctx) error`, `Stop() error`, `IsHealthy() bool`, `Port() int`

- [ ] **Step 1: Write tests**

```go
// internal/training/llama_test.go
package training

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestLlamaServer_NewDefaults(t *testing.T) {
    ls := NewLlamaServer(LlamaConfig{ModelsDir: "/tmp/models"})
    if ls.Port() != 8090 {
        t.Errorf("expected default port 8090, got %d", ls.Port())
    }
}

func TestLlamaServer_IsHealthy_MockServer(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    }))
    defer srv.Close()

    ls := &LlamaServer{healthURL: srv.URL + "/health"}
    if !ls.IsHealthy() {
        t.Error("should be healthy")
    }
}

func TestLlamaServer_IsHealthy_NoServer(t *testing.T) {
    ls := &LlamaServer{healthURL: "http://127.0.0.1:19999/health"}
    if ls.IsHealthy() {
        t.Error("should not be healthy with no server")
    }
}
```

- [ ] **Step 2: Implement LlamaServer**

```go
// internal/training/llama.go
package training

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/exec"
    "time"
)

type LlamaConfig struct {
    ModelsDir string
    Port      int
    MaxModels int
    Binary    string // path to llama-server binary
}

type LlamaServer struct {
    cfg       LlamaConfig
    cmd       *exec.Cmd
    cancel    context.CancelFunc
    healthURL string
}

func NewLlamaServer(cfg LlamaConfig) *LlamaServer {
    if cfg.Port == 0 {
        cfg.Port = 8090
    }
    if cfg.MaxModels == 0 {
        cfg.MaxModels = 4
    }
    if cfg.Binary == "" {
        cfg.Binary = "llama-server"
    }
    return &LlamaServer{
        cfg:       cfg,
        healthURL: fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Port),
    }
}

func (l *LlamaServer) Start(ctx context.Context) error {
    if err := os.MkdirAll(l.cfg.ModelsDir, 0755); err != nil {
        return fmt.Errorf("training: create models dir: %w", err)
    }

    procCtx, cancel := context.WithCancel(ctx)
    l.cancel = cancel

    l.cmd = exec.CommandContext(procCtx, l.cfg.Binary,
        "--models-dir", l.cfg.ModelsDir,
        "--models-max", fmt.Sprintf("%d", l.cfg.MaxModels),
        "--port", fmt.Sprintf("%d", l.cfg.Port),
        "--host", "127.0.0.1",
        "--metrics",
    )
    l.cmd.Stdout = os.Stderr
    l.cmd.Stderr = os.Stderr

    if err := l.cmd.Start(); err != nil {
        cancel()
        return fmt.Errorf("training: llama-server start: %w", err)
    }

    fmt.Fprintf(os.Stderr, "[training] llama-server started (pid=%d, port=%d, models_dir=%s)\n",
        l.cmd.Process.Pid, l.cfg.Port, l.cfg.ModelsDir)

    go func() {
        l.cmd.Wait()
        if procCtx.Err() == nil {
            fmt.Fprintf(os.Stderr, "[training] llama-server exited unexpectedly\n")
        }
    }()

    return nil
}

func (l *LlamaServer) WaitForHealth(timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    client := &http.Client{Timeout: 2 * time.Second}
    for time.Now().Before(deadline) {
        resp, err := client.Get(l.healthURL)
        if err == nil {
            resp.Body.Close()
            if resp.StatusCode == http.StatusOK {
                return nil
            }
        }
        time.Sleep(200 * time.Millisecond)
    }
    return fmt.Errorf("training: llama-server health timeout after %v", timeout)
}

func (l *LlamaServer) Stop() error {
    if l.cancel != nil {
        l.cancel()
    }
    if l.cmd != nil && l.cmd.Process != nil {
        l.cmd.Process.Kill()
    }
    fmt.Fprintf(os.Stderr, "[training] llama-server stopped\n")
    return nil
}

func (l *LlamaServer) IsHealthy() bool {
    client := &http.Client{Timeout: 2 * time.Second}
    resp, err := client.Get(l.healthURL)
    if err != nil {
        return false
    }
    resp.Body.Close()
    return resp.StatusCode == http.StatusOK
}

func (l *LlamaServer) Port() int { return l.cfg.Port }
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/training/ -run "TestLlama" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/training/llama.go internal/training/llama_test.go
git commit -m "feat(training): add llama-server lifecycle manager"
```

---

### Task 5: Dataset Extractor

**Files:**
- Create: `internal/training/extractor.go`
- Create: `internal/training/extractor_test.go`

**Interfaces:**
- Consumes: `training.Store` (Task 1)
- Produces: `training.Extractor` with `Extract(store *Store, category string, limit int, evalRatio float64) (*Dataset, error)` where `Dataset{TrainFile, EvalFile, TrainCount, EvalCount string/int}`

- [ ] **Step 1: Write test**

```go
// internal/training/extractor_test.go
package training

import (
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

func TestExtract_SplitsTrainEval(t *testing.T) {
    dbPath := filepath.Join(t.TempDir(), "test.db")
    store, _ := NewStore(dbPath)
    defer store.Close()

    for i := 0; i < 100; i++ {
        store.CaptureTrace(TraceEntry{
            Category:  "code",
            Prompt:    `[{"role":"user","content":"test"}]`,
            Response:  "response",
            ModelUsed: "frontier",
        })
    }

    outDir := t.TempDir()
    ds, err := Extract(store, "code", 100, 0.1, outDir)
    if err != nil {
        t.Fatalf("Extract: %v", err)
    }
    if ds.TrainCount != 90 {
        t.Errorf("train count = %d, want 90", ds.TrainCount)
    }
    if ds.EvalCount != 10 {
        t.Errorf("eval count = %d, want 10", ds.EvalCount)
    }

    // Verify train file is valid JSONL
    data, _ := os.ReadFile(ds.TrainFile)
    var first map[string]interface{}
    lines := splitLines(data)
    json.Unmarshal([]byte(lines[0]), &first)
    if first["prompt"] == nil {
        t.Error("train file should have prompt field")
    }
}

func splitLines(data []byte) []string {
    var lines []string
    start := 0
    for i, b := range data {
        if b == '\n' {
            if i > start {
                lines = append(lines, string(data[start:i]))
            }
            start = i + 1
        }
    }
    if start < len(data) {
        lines = append(lines, string(data[start:]))
    }
    return lines
}
```

- [ ] **Step 2: Implement Extractor**

```go
// internal/training/extractor.go
package training

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
)

type Dataset struct {
    TrainFile  string
    EvalFile   string
    TrainCount int
    EvalCount  int
    Category   string
}

// Extract pulls traces from the store, splits into train/eval, writes JSONL files.
func Extract(store *Store, category string, limit int, evalRatio float64, outDir string) (*Dataset, error) {
    traces, err := store.ExtractForTraining(category, limit)
    if err != nil {
        return nil, fmt.Errorf("extract: query: %w", err)
    }
    if len(traces) == 0 {
        return nil, fmt.Errorf("extract: no traces for category %q", category)
    }

    evalCount := int(float64(len(traces)) * evalRatio)
    if evalCount < 1 {
        evalCount = 1
    }
    trainCount := len(traces) - evalCount

    if err := os.MkdirAll(outDir, 0755); err != nil {
        return nil, err
    }

    trainPath := filepath.Join(outDir, category+"_train.jsonl")
    evalPath := filepath.Join(outDir, category+"_eval.jsonl")

    if err := writeJSONL(trainPath, traces[:trainCount]); err != nil {
        return nil, err
    }
    if err := writeJSONL(evalPath, traces[trainCount:]); err != nil {
        return nil, err
    }

    return &Dataset{
        TrainFile:  trainPath,
        EvalFile:   evalPath,
        TrainCount: trainCount,
        EvalCount:  evalCount,
        Category:   category,
    }, nil
}

type jsonlEntry struct {
    Prompt   string `json:"prompt"`
    Response string `json:"response"`
    Model    string `json:"model_used"`
}

func writeJSONL(path string, traces []TraceEntry) error {
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    for _, t := range traces {
        enc.Encode(jsonlEntry{Prompt: t.Prompt, Response: t.Response, Model: t.ModelUsed})
    }
    return nil
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/training/ -run "TestExtract" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/training/extractor.go internal/training/extractor_test.go
git commit -m "feat(training): add dataset extractor (SQLite → JSONL with train/eval split)"
```

---

### Task 6: Training Subprocess Runner

**Files:**
- Create: `internal/training/runner.go`
- Create: `internal/training/runner_test.go`

**Interfaces:**
- Consumes: `Dataset` (Task 5), `config.TrainingCategory`, `config.TrainingConfig`
- Produces: `training.Runner` with `Run(ctx, RunConfig) (*RunResult, error)` where `RunResult{GGUFPath, Duration, ExitCode}`

- [ ] **Step 1: Write test (mocks the subprocess)**

```go
// internal/training/runner_test.go
package training

import (
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestRunner_GeneratesScript(t *testing.T) {
    outDir := t.TempDir()
    cfg := RunConfig{
        Backend:     "unsloth",
        Algorithm:   "dpo",
        BaseModel:   "unsloth/Qwen3.5-4B",
        DatasetPath: "/tmp/code_train.jsonl",
        OutputDir:   outDir,
        ScriptsDir:  outDir,
    }

    scriptPath, err := generateTrainingScript(cfg)
    if err != nil {
        t.Fatalf("generateTrainingScript: %v", err)
    }

    content, _ := os.ReadFile(scriptPath)
    script := string(content)

    if len(script) == 0 {
        t.Fatal("script should not be empty")
    }
    // Should contain the model name
    if !contains(script, "Qwen3.5-4B") {
        t.Error("script should reference the base model")
    }
    // Should contain the algorithm
    if !contains(script, "dpo") || !contains(script, "DPO") {
        t.Error("script should reference the algorithm")
    }
}

func TestRunner_Timeout(t *testing.T) {
    cfg := RunConfig{
        Backend:    "test",
        ScriptsDir: t.TempDir(),
        OutputDir:  t.TempDir(),
        TimeoutSec: 1,
    }

    // Write a script that sleeps forever
    scriptPath := filepath.Join(cfg.ScriptsDir, "train.py")
    os.WriteFile(scriptPath, []byte("import time; time.sleep(999)"), 0755)

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    _, err := runSubprocess(ctx, "python3", scriptPath, cfg.TimeoutSec)
    if err == nil {
        t.Fatal("expected timeout error")
    }
}

func contains(s, sub string) bool {
    return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
    for i := 0; i <= len(s)-len(sub); i++ {
        if s[i:i+len(sub)] == sub {
            return true
        }
    }
    return false
}
```

- [ ] **Step 2: Implement Runner**

```go
// internal/training/runner.go
package training

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "time"
)

type RunConfig struct {
    Backend     string // "unsloth" or "mlx-lm-lora"
    Algorithm   string // "sft", "dpo", "grpo", etc.
    BaseModel   string // HF repo or MLX repo
    DatasetPath string
    OutputDir   string
    ScriptsDir  string
    TimeoutSec  int
}

type RunResult struct {
    GGUFPath string
    Duration time.Duration
    ExitCode int
}

func generateTrainingScript(cfg RunConfig) (string, error) {
    if err := os.MkdirAll(cfg.ScriptsDir, 0755); err != nil {
        return "", err
    }

    var script string
    switch cfg.Backend {
    case "unsloth":
        script = generateUnslothScript(cfg)
    case "mlx-lm-lora":
        script = generateMLXScript(cfg)
    default:
        return "", fmt.Errorf("unknown backend: %s", cfg.Backend)
    }

    path := filepath.Join(cfg.ScriptsDir, "train.py")
    if err := os.WriteFile(path, []byte(script), 0755); err != nil {
        return "", err
    }
    return path, nil
}

func generateUnslothScript(cfg RunConfig) string {
    trainerClass := "SFTTrainer"
    configClass := "SFTConfig"
    switch cfg.Algorithm {
    case "dpo":
        trainerClass = "DPOTrainer"
        configClass = "DPOConfig"
    case "grpo":
        trainerClass = "GRPOTrainer"
        configClass = "GRPOConfig"
    case "orpo":
        trainerClass = "ORPOTrainer"
        configClass = "ORPOConfig"
    }

    return fmt.Sprintf(`#!/usr/bin/env python3
import sys
from unsloth import FastLanguageModel
from trl import %s, %s
from datasets import load_dataset

print("[training] Loading model: %s")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="%s",
    load_in_4bit=True,
    max_seq_length=4096,
)
model = FastLanguageModel.get_peft_model(model, r=64, lora_alpha=16)

print("[training] Loading dataset: %s")
dataset = load_dataset("json", data_files="%s")

print("[training] Starting %s training...")
trainer = %s(
    model=model,
    train_dataset=dataset["train"],
    args=%s(
        output_dir="%s",
        num_train_epochs=3,
        per_device_train_batch_size=2,
        logging_steps=10,
    ),
)
trainer.train()

print("[training] Exporting GGUF...")
model.save_pretrained_gguf("%s", tokenizer, quantization_method="q4_k_m")
print("[training] Done!")
`, trainerClass, configClass,
        cfg.BaseModel, cfg.BaseModel,
        cfg.DatasetPath, cfg.DatasetPath,
        cfg.Algorithm, trainerClass, configClass,
        cfg.OutputDir, cfg.OutputDir)
}

func generateMLXScript(cfg RunConfig) string {
    return fmt.Sprintf(`#!/bin/bash
set -e
echo "[training] Starting mlx-lm-lora %s training..."
mlx-lm-lora \
  --train-mode %s \
  --model %s \
  --data %s \
  --output %s \
  --batch-size 2 \
  --epochs 3

echo "[training] Exporting GGUF..."
mlx-lm-lora \
  --export-gguf \
  --model %s \
  --output %s/model.gguf \
  --quantize q4_k_m

echo "[training] Done!"
`, cfg.Algorithm, cfg.Algorithm, cfg.BaseModel, cfg.DatasetPath, cfg.OutputDir, cfg.OutputDir, cfg.OutputDir)
}

func runSubprocess(ctx context.Context, command, scriptPath string, timeoutSec int) (*RunResult, error) {
    if timeoutSec == 0 {
        timeoutSec = 43200 // 12 hours default
    }
    ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
    defer cancel()

    start := time.Now()
    cmd := exec.CommandContext(ctx, command, scriptPath)
    cmd.Stdout = os.Stderr
    cmd.Stderr = os.Stderr

    err := cmd.Run()
    duration := time.Since(start)

    exitCode := 0
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            exitCode = exitErr.ExitCode()
        } else {
            return nil, fmt.Errorf("training subprocess: %w", err)
        }
    }

    return &RunResult{Duration: duration, ExitCode: exitCode}, err
}

// Run executes the full training pipeline: generate script → run subprocess → find GGUF.
func Run(ctx context.Context, cfg RunConfig) (*RunResult, error) {
    scriptPath, err := generateTrainingScript(cfg)
    if err != nil {
        return nil, fmt.Errorf("training: generate script: %w", err)
    }

    fmt.Fprintf(os.Stderr, "[training] running %s %s (model=%s, dataset=%s)\n",
        cfg.Backend, cfg.Algorithm, cfg.BaseModel, cfg.DatasetPath)

    command := "python3"
    if cfg.Backend == "mlx-lm-lora" {
        command = "bash"
    }

    result, err := runSubprocess(ctx, command, scriptPath, cfg.TimeoutSec)
    if err != nil {
        return result, fmt.Errorf("training: subprocess failed: %w", err)
    }

    // Find GGUF in output dir
    ggufPath := findGGUF(cfg.OutputDir)
    if ggufPath != "" && result != nil {
        result.GGUFPath = ggufPath
    }

    return result, nil
}

func findGGUF(dir string) string {
    entries, _ := os.ReadDir(dir)
    for _, e := range entries {
        if filepath.Ext(e.Name()) == ".gguf" {
            return filepath.Join(dir, e.Name())
        }
    }
    // Check subdirectories (unsloth puts it in a subdir)
    filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err == nil && filepath.Ext(path) == ".gguf" {
            dir = path // reuse variable as found path
        }
        return nil
    })
    if filepath.Ext(dir) == ".gguf" {
        return dir
    }
    return ""
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/training/ -run "TestRunner" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/training/runner.go internal/training/runner_test.go
git commit -m "feat(training): add training subprocess runner with script generation"
```

---

### Task 7: Evaluator (LLM-as-Judge)

**Files:**
- Create: `internal/training/evaluator.go`
- Create: `internal/training/evaluator_test.go`

**Interfaces:**
- Consumes: `Dataset.EvalFile` (Task 5), llama-server endpoint, LLM Judge endpoint
- Produces: `training.Evaluate(cfg EvalConfig) (*EvalResult, error)` where `EvalResult{ScoreLocal, ScoreFrontier, Ratio float64, Passed bool}`

This task implements the LLM-as-judge evaluation: sends prompts to local model, looks up frontier response from the dataset, sends both to a judge model for scoring.

- [ ] **Step 1-4: Implement + test** (following same pattern as above tasks)

- [ ] **Step 5: Commit**

```bash
git add internal/training/evaluator.go internal/training/evaluator_test.go
git commit -m "feat(training): add LLM-as-judge evaluator"
```

---

### Task 8: Pipeline Orchestrator

**Files:**
- Create: `internal/training/pipeline.go`
- Create: `internal/training/pipeline_test.go`

**Interfaces:**
- Consumes: All previous tasks (Store, Extractor, Runner, Registry, LlamaServer, Evaluator)
- Produces: `training.Pipeline` with `Run(ctx, category string) error`, `Status(category string) PipelineState`

The orchestrator ties all stages together: extract → dataset → train → export → deploy → eval → promote.

- [ ] **Step 1-4: Implement + test**

- [ ] **Step 5: Commit**

```bash
git add internal/training/pipeline.go internal/training/pipeline_test.go
git commit -m "feat(training): add pipeline orchestrator (full stage sequence)"
```

---

### Task 9: Auto-Trigger

**Files:**
- Create: `internal/training/trigger.go`
- Create: `internal/training/trigger_test.go`

**Interfaces:**
- Consumes: `Store.CountByCategory`, `Pipeline.Run`, `config.TrainingCategory`
- Produces: `training.AutoTrigger` with `Start(ctx)`, `Stop()`

Goroutine that checks trace counts every 60 seconds and fires the pipeline when threshold is met.

- [ ] **Step 1-4: Implement + test**

- [ ] **Step 5: Commit**

```bash
git add internal/training/trigger.go internal/training/trigger_test.go
git commit -m "feat(training): add auto-trigger (threshold-based pipeline activation)"
```

---

### Task 10: Sidecar Wiring

**Files:**
- Modify: `internal/gateway/sidecar.go` (init training store, capturer, llama-server, auto-trigger)
- Modify: `internal/config/config.go` (add `Training TrainingConfig` field)

**Interfaces:**
- Consumes: All training components
- Produces: Training pipeline integrated into gateway lifecycle (start on boot, stop on shutdown, capture on every request)

- [ ] **Step 1-4: Wire into sidecar Run()**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(training): wire pipeline into sidecar lifecycle"
```

---

### Task 11: CLI Commands

**Files:**
- Create/modify: `cli/defenseclaw/commands/cmd_training.py`
- Modify: `cli/defenseclaw/config.py` (add TrainingConfig)

**Interfaces:**
- Consumes: Gateway API (HTTP calls to trigger training, get status)
- Produces: `defenseclaw training {enable, disable, status, run, eval, promote, rollback, models, traces}`

- [ ] **Step 1-4: Implement all CLI commands**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(cli): add training pipeline CLI commands"
```

---

## Dependency Graph

```
Task 1 (Store + Config)
  ├── Task 2 (Capturer) → Task 10 (Sidecar wiring)
  ├── Task 3 (Registry) → Task 8 (Pipeline)
  ├── Task 4 (llama-server) → Task 8 (Pipeline)
  ├── Task 5 (Extractor) → Task 6 (Runner) → Task 8 (Pipeline)
  └── Task 7 (Evaluator) → Task 8 (Pipeline)

Task 8 (Pipeline) → Task 9 (Trigger) → Task 10 (Sidecar)
Task 10 (Sidecar) → Task 11 (CLI)
```

## Execution Order

Tasks 1-7 can be partially parallelized. Recommended serial order:
1. Task 1 (foundation — everything depends on it)
2. Tasks 2, 3, 4, 5 (independent, can run in parallel)
3. Task 6 (depends on 5)
4. Task 7 (independent of 6)
5. Task 8 (depends on 2-7)
6. Task 9 (depends on 8)
7. Task 10 (depends on 8, 9)
8. Task 11 (depends on 10)
