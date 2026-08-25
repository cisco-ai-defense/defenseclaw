## Task 6: Go CGO Bindings and Stub

**Files:**
- Create: `internal/training/grpo_cgo.go`
- Create: `internal/training/grpo_stub.go`
- Create: `internal/training/grpo_config.go`

**Interfaces:**
- Consumes: C library from Tasks 1-5
- Produces: `GrpoEngine` Go struct with methods matching the C API, `GrpoLocalConfig` type

- [ ] **Step 1: Create `grpo_config.go` with configuration types**

```go
// internal/training/grpo_config.go
package training

// GrpoLocalConfig holds all settings for a grpo-local training run.
type GrpoLocalConfig struct {
    PolicyGGUF    string
    ReferenceGGUF string
    RewardGGUF    string

    GroupSize      int
    MaxGenLength   int
    ClipEpsilon    float64
    KLCoef         float64
    Temperature    float64
    TopP           float64
    LearningRate   float64
    GradAccumSteps int

    LoRARank    int
    LoRAAlpha   int
    LoRATargets string

    MemoryMode string
    NumThreads int

    RewardFuncs []RewardSpec

    MaxSteps        int
    CheckpointEvery int
    DatasetPath     string
    OutputDir       string
}

// RewardSpec defines a single reward function with its weight.
type RewardSpec struct {
    Type   string
    Params map[string]string
    Weight float64
}

// ParseRewardFuncs parses config strings like "exec:timeout=10,lang=python" into RewardSpecs.
func ParseRewardFuncs(specs []string) []RewardSpec {
    result := make([]RewardSpec, 0, len(specs))
    for _, spec := range specs {
        rs := RewardSpec{Weight: 1.0, Params: make(map[string]string)}
        // Parse "type:key=val,key=val" format
        parts := splitFirst(spec, ':')
        rs.Type = parts[0]
        if len(parts) > 1 {
            for _, kv := range splitAll(parts[1], ',') {
                pair := splitFirst(kv, '=')
                if len(pair) == 2 {
                    rs.Params[pair[0]] = pair[1]
                }
            }
        }
        result = append(result, rs)
    }
    return result
}

func splitFirst(s string, sep byte) []string {
    for i := range s {
        if s[i] == sep {
            return []string{s[:i], s[i+1:]}
        }
    }
    return []string{s}
}

func splitAll(s string, sep byte) []string {
    var parts []string
    start := 0
    for i := range s {
        if s[i] == sep {
            parts = append(parts, s[start:i])
            start = i + 1
        }
    }
    parts = append(parts, s[start:])
    return parts
}
```

- [ ] **Step 2: Create `grpo_cgo.go` with CGO bindings**

```go
//go:build cgo && grpo_engine

// internal/training/grpo_cgo.go
package training

/*
#cgo CFLAGS: -I${SRCDIR}/grpo_engine -O3 -ffp-contract=off
#cgo linux CFLAGS: -fopenmp
#cgo linux LDFLAGS: -L${SRCDIR}/grpo_engine -lgrpo_stream -lm -lgomp
#cgo darwin LDFLAGS: -L${SRCDIR}/grpo_engine -lgrpo_stream -lm
#include "grpo.h"
#include <stdlib.h>
*/
import "C"
import (
    "fmt"
    "unsafe"
)

// GrpoEngine wraps the C library context.
type GrpoEngine struct {
    ctx *C.GrpoCtx
}

// NewGrpoEngine initializes the C engine with the given config.
func NewGrpoEngine(cfg GrpoLocalConfig) (*GrpoEngine, error) {
    policyPath := C.CString(cfg.PolicyGGUF)
    defer C.free(unsafe.Pointer(policyPath))

    var refPath, rewPath *C.char
    if cfg.ReferenceGGUF != "" {
        refPath = C.CString(cfg.ReferenceGGUF)
        defer C.free(unsafe.Pointer(refPath))
    }
    if cfg.RewardGGUF != "" {
        rewPath = C.CString(cfg.RewardGGUF)
        defer C.free(unsafe.Pointer(rewPath))
    }

    var targets *C.char
    if cfg.LoRATargets != "" {
        targets = C.CString(cfg.LoRATargets)
        defer C.free(unsafe.Pointer(targets))
    }

    memMode := 0 // auto-detect
    switch cfg.MemoryMode {
    case "minimal":
        memMode = 0
    case "standard":
        memMode = 1
    case "comfort":
        memMode = 2
    }

    ccfg := C.GrpoConfig{
        policy_gguf:      policyPath,
        reference_gguf:   refPath,
        reward_gguf:      rewPath,
        memory_mode:      C.int(memMode),
        lora_rank:        C.int(cfg.LoRARank),
        lora_alpha:       C.int(cfg.LoRAAlpha),
        lora_targets:     targets,
        max_seq_len:      C.int(2048),
        num_threads:      C.int(cfg.NumThreads),
        use_direct_io:    C.int(1),
        layer_buffer_bytes: 0, // auto-size
    }

    ctx := C.grpo_init(&ccfg)
    if ctx == nil {
        return nil, fmt.Errorf("grpo_init failed")
    }
    return &GrpoEngine{ctx: ctx}, nil
}

func (e *GrpoEngine) Generate(prompt []int, maxLen int, temp, topP float32) (tokens []int, logprobs []float32, err error) {
    output := make([]C.int, maxLen)
    lp := make([]C.float, maxLen)
    promptC := make([]C.int, len(prompt))
    for i, t := range prompt {
        promptC[i] = C.int(t)
    }

    n := C.grpo_generate(e.ctx, &promptC[0], C.int(len(prompt)),
        &output[0], C.int(maxLen), &lp[0], C.float(temp), C.float(topP))
    if n < 0 {
        return nil, nil, fmt.Errorf("generation failed")
    }

    tokens = make([]int, int(n))
    logprobs = make([]float32, int(n))
    for i := 0; i < int(n); i++ {
        tokens[i] = int(output[i])
        logprobs[i] = float32(lp[i])
    }
    return tokens, logprobs, nil
}

func (e *GrpoEngine) PolicyLogprobs(tokens []int) ([]float32, error) {
    tc := make([]C.int, len(tokens))
    for i, t := range tokens {
        tc[i] = C.int(t)
    }
    lp := make([]C.float, len(tokens))
    ret := C.grpo_policy_logprobs(e.ctx, &tc[0], C.int(len(tokens)), &lp[0])
    if ret != 0 {
        return nil, fmt.Errorf("policy logprobs failed")
    }
    result := make([]float32, len(tokens))
    for i := range result {
        result[i] = float32(lp[i])
    }
    return result, nil
}

func (e *GrpoEngine) RefLogprobs(tokens []int) ([]float32, error) {
    tc := make([]C.int, len(tokens))
    for i, t := range tokens {
        tc[i] = C.int(t)
    }
    lp := make([]C.float, len(tokens))
    ret := C.grpo_ref_logprobs(e.ctx, &tc[0], C.int(len(tokens)), &lp[0])
    if ret != 0 {
        return nil, fmt.Errorf("ref logprobs failed")
    }
    result := make([]float32, len(tokens))
    for i := range result {
        result[i] = float32(lp[i])
    }
    return result, nil
}

func (e *GrpoEngine) Backward(advantages, policyLP, oldLP, refLP []float32, G, seqLen int, clipEps, klCoef float32) error {
    ret := C.grpo_backward(e.ctx,
        (*C.float)(unsafe.Pointer(&advantages[0])),
        (*C.float)(unsafe.Pointer(&policyLP[0])),
        (*C.float)(unsafe.Pointer(&oldLP[0])),
        (*C.float)(unsafe.Pointer(&refLP[0])),
        C.int(G), C.int(seqLen), C.float(clipEps), C.float(klCoef))
    if ret != 0 {
        return fmt.Errorf("backward failed")
    }
    return nil
}

func (e *GrpoEngine) AdamStep(lr, beta1, beta2, eps float32, step int) error {
    ret := C.grpo_adam_step(e.ctx, C.float(lr), C.float(beta1), C.float(beta2), C.float(eps), C.int(step))
    if ret != 0 {
        return fmt.Errorf("adam step failed")
    }
    return nil
}

func (e *GrpoEngine) SaveLoRA(path string) error {
    p := C.CString(path)
    defer C.free(unsafe.Pointer(p))
    if C.grpo_save_lora(e.ctx, p) != 0 {
        return fmt.Errorf("save lora failed")
    }
    return nil
}

func (e *GrpoEngine) LoadLoRA(path string) error {
    p := C.CString(path)
    defer C.free(unsafe.Pointer(p))
    if C.grpo_load_lora(e.ctx, p) != 0 {
        return fmt.Errorf("load lora failed")
    }
    return nil
}

func (e *GrpoEngine) ExportMergedGGUF(path string) error {
    p := C.CString(path)
    defer C.free(unsafe.Pointer(p))
    if C.grpo_export_merged_gguf(e.ctx, p) != 0 {
        return fmt.Errorf("export merged gguf failed")
    }
    return nil
}

func (e *GrpoEngine) Stats() GrpoStats {
    s := C.grpo_stats(e.ctx)
    return GrpoStats{
        Steps:             int64(s.steps),
        TotalGenSeconds:   float64(s.total_gen_seconds),
        TotalStreamSeconds: float64(s.total_stream_seconds),
        TotalBackwardSeconds: float64(s.total_backward_seconds),
        BytesStreamed:     uint64(s.bytes_streamed),
        LastLoss:          float32(s.last_loss),
        LastRewardMean:    float32(s.last_reward_mean),
    }
}

func (e *GrpoEngine) Close() {
    if e.ctx != nil {
        C.grpo_free(e.ctx)
        e.ctx = nil
    }
}

// GrpoEngineAvailable returns true when the C engine is compiled in.
func GrpoEngineAvailable() bool { return true }
```

- [ ] **Step 3: Create `grpo_stub.go` for builds without C library**

```go
//go:build !cgo || !grpo_engine

// internal/training/grpo_stub.go
package training

import (
    "context"
    "fmt"
)

// GrpoEngineAvailable returns false when the C engine is not compiled in.
func GrpoEngineAvailable() bool { return false }

// RunGrpoLocal is a stub that returns an error when the C engine is unavailable.
func RunGrpoLocal(ctx context.Context, cfg GrpoLocalConfig) (*RunResult, error) {
    return nil, fmt.Errorf("grpo-local backend not available: rebuild with CGO_ENABLED=1 -tags grpo_engine")
}
```

- [ ] **Step 4: Verify Go compilation (without actually linking C — just syntax check)**

Run: `go vet ./internal/training/`
Expected: No errors on grpo_stub.go path.

- [ ] **Step 5: Commit**

```bash
git add internal/training/grpo_config.go internal/training/grpo_cgo.go internal/training/grpo_stub.go
git commit -m "feat(training): add CGO bindings and stub for grpo-local engine"
```

---

