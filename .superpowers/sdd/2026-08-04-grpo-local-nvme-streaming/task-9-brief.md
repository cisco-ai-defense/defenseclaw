## Task 9: End-to-End Test

**Files:**
- Create: `internal/training/grpo_runner_test.go`
- Create: `internal/training/grpo_engine/testdata/tiny_model.gguf` (via script)

**Interfaces:**
- Consumes: All previous tasks
- Produces: Passing E2E test that verifies the full GRPO loop works on a tiny model

- [ ] **Step 1: Create a script to generate tiny test model GGUF**

```python
#!/usr/bin/env python3
"""Generate a tiny 2-layer GGUF model for testing.
Run once: python3 scripts/gen_tiny_gguf.py > internal/training/grpo_engine/testdata/tiny_model.gguf
"""
# This creates a minimal GGUF with:
# - 2 layers, hidden_dim=64, intermediate_dim=128, vocab=256
# - Random Q4_K weights (just needs valid structure, not trained values)
# ... (actual implementation generates GGUF binary format)
```

- [ ] **Step 2: Write E2E test**

```go
// internal/training/grpo_runner_test.go
//go:build cgo && grpo_engine

package training

import (
    "context"
    "os"
    "path/filepath"
    "testing"
)

func TestGrpoRunnerE2E(t *testing.T) {
    tinyModel := filepath.Join("grpo_engine", "testdata", "tiny_model.gguf")
    if _, err := os.Stat(tinyModel); err != nil {
        t.Skip("tiny_model.gguf not found — run gen_tiny_gguf.py first")
    }

    tmpDir := t.TempDir()

    // Create minimal dataset
    datasetPath := filepath.Join(tmpDir, "prompts.jsonl")
    os.WriteFile(datasetPath, []byte(
        `{"prompt_tokens": [1, 5, 10, 15], "ground_truth": "hello"}`+"\n"+
        `{"prompt_tokens": [1, 20, 25, 30], "ground_truth": "world"}`+"\n",
    ), 0644)

    cfg := GrpoLocalConfig{
        PolicyGGUF:   tinyModel,
        GroupSize:     2,
        MaxGenLength:  8,
        ClipEpsilon:   0.2,
        Temperature:   1.0,
        TopP:          0.9,
        LearningRate:  1e-3,
        LoRARank:      4,
        LoRAAlpha:     4,
        LoRATargets:   "q,k,v,o,gate,up,down",
        MemoryMode:    "comfort",
        RewardFuncs:   []RewardSpec{{Type: "length", Params: map[string]string{"min": "1", "max": "10"}, Weight: 1.0}},
        MaxSteps:      5,
        CheckpointEvery: 2,
        DatasetPath:   datasetPath,
        OutputDir:     tmpDir,
    }

    result, err := RunGrpoLocal(context.Background(), cfg)
    if err != nil {
        t.Fatalf("RunGrpoLocal failed: %v", err)
    }

    if result.GGUFPath == "" {
        t.Fatal("no merged GGUF produced")
    }
    if _, err := os.Stat(result.GGUFPath); err != nil {
        t.Fatalf("merged GGUF not found at %s", result.GGUFPath)
    }

    // Verify checkpoint was created
    checkpoint := filepath.Join(tmpDir, "checkpoint.dclora")
    if _, err := os.Stat(checkpoint); err != nil {
        t.Fatal("no checkpoint created")
    }

    t.Logf("GRPO E2E completed in %v, output: %s", result.Duration, result.GGUFPath)
}
```

- [ ] **Step 3: Build C library and run E2E test**

Run:
```bash
make -C internal/training/grpo_engine
CGO_ENABLED=1 go test -tags grpo_engine ./internal/training/ -run TestGrpoRunnerE2E -v -timeout 60s
```
Expected: PASS (test model is tiny, runs in seconds)

- [ ] **Step 4: Commit**

```bash
git add internal/training/grpo_runner_test.go internal/training/grpo_engine/testdata/
git commit -m "test(training): add E2E test for grpo-local training loop"
```

---

