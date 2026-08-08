//go:build cgo && grpo_engine

package training

import (
    "context"
    "os"
    "testing"
    "time"
)

func TestGrpo_100Steps(t *testing.T) {
    if _, err := os.Stat("/tmp/qwen3-8b.gguf"); err != nil { t.Skip("no model") }
    if _, err := os.Stat("/tmp/grpo-test/hermes_100_prompts.jsonl"); err != nil { t.Skip("no data") }

    cfg := GrpoLocalConfig{
        PolicyGGUF: "/tmp/qwen3-8b.gguf",
        GroupSize: 2, MaxGenLength: 32,
        ClipEpsilon: 0.2, Temperature: 0.8, TopP: 0.9,
        LearningRate: 1e-4, LoRARank: 4, LoRAAlpha: 4,
        LoRATargets: "q,k,v,o,gate,up,down", MemoryMode: "comfort",
        MaxSteps: 100, CheckpointEvery: 100,
        DatasetPath: "/tmp/grpo-test/hermes_100_prompts.jsonl",
        OutputDir: t.TempDir(),
    }

    start := time.Now()
    _, err := RunGrpoLocal(context.Background(), cfg)
    t.Logf("Elapsed: %v, err: %v", time.Since(start), err)
}
