package training

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateScript_Unsloth_DPO(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "dpo",
		BaseModel:   "unsloth/mistral-7b",
		DatasetPath: "/data/train.jsonl",
		OutputDir:   "/output",
	}

	script, err := generateTrainingScript(cfg)
	if err != nil {
		t.Fatalf("generateTrainingScript failed: %v", err)
	}

	// Verify script contains expected elements
	if !strings.Contains(script, "DPOTrainer") {
		t.Errorf("script does not contain DPOTrainer")
	}
	if !strings.Contains(script, "DPOConfig") {
		t.Errorf("script does not contain DPOConfig")
	}
	if !strings.Contains(script, "unsloth/mistral-7b") {
		t.Errorf("script does not contain base model name")
	}
	if !strings.Contains(script, "/data/train.jsonl") {
		t.Errorf("script does not contain dataset path")
	}
	if !strings.Contains(script, "from trl import DPOTrainer, DPOConfig") {
		t.Errorf("script does not contain correct import")
	}
	if !strings.Contains(script, "save_pretrained_gguf") {
		t.Errorf("script does not contain GGUF export")
	}
}

func TestGenerateScript_Unsloth_SFT(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "sft",
		BaseModel:   "meta-llama/Llama-2-7b-hf",
		DatasetPath: "/data/sft.jsonl",
		OutputDir:   "/output",
	}

	script, err := generateTrainingScript(cfg)
	if err != nil {
		t.Fatalf("generateTrainingScript failed: %v", err)
	}

	// Verify script contains expected elements
	if !strings.Contains(script, "SFTTrainer") {
		t.Errorf("script does not contain SFTTrainer")
	}
	if !strings.Contains(script, "SFTConfig") {
		t.Errorf("script does not contain SFTConfig")
	}
	if !strings.Contains(script, "meta-llama/Llama-2-7b-hf") {
		t.Errorf("script does not contain base model name")
	}
	if !strings.Contains(script, "/data/sft.jsonl") {
		t.Errorf("script does not contain dataset path")
	}
	if !strings.Contains(script, "from trl import SFTTrainer, SFTConfig") {
		t.Errorf("script does not contain correct import")
	}
}

func TestGenerateScript_Unsloth_GRPO(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "grpo",
		BaseModel:   "unsloth/llama-3-8b",
		DatasetPath: "/data/grpo.jsonl",
		OutputDir:   "/output",
	}

	script, err := generateTrainingScript(cfg)
	if err != nil {
		t.Fatalf("generateTrainingScript failed: %v", err)
	}

	if !strings.Contains(script, "GRPOTrainer") {
		t.Errorf("script does not contain GRPOTrainer")
	}
	if !strings.Contains(script, "GRPOConfig") {
		t.Errorf("script does not contain GRPOConfig")
	}
}

func TestGenerateScript_Unsloth_ORPO(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "orpo",
		BaseModel:   "unsloth/phi-2",
		DatasetPath: "/data/orpo.jsonl",
		OutputDir:   "/output",
	}

	script, err := generateTrainingScript(cfg)
	if err != nil {
		t.Fatalf("generateTrainingScript failed: %v", err)
	}

	if !strings.Contains(script, "ORPOTrainer") {
		t.Errorf("script does not contain ORPOTrainer")
	}
	if !strings.Contains(script, "ORPOConfig") {
		t.Errorf("script does not contain ORPOConfig")
	}
}

func TestGenerateScript_MLX(t *testing.T) {
	cfg := RunConfig{
		Backend:     "mlx-lm-lora",
		Algorithm:   "dpo",
		BaseModel:   "mlx-community/Mistral-7B-v0.1-4bit",
		DatasetPath: "/data/train.jsonl",
		OutputDir:   "/output",
	}

	script, err := generateTrainingScript(cfg)
	if err != nil {
		t.Fatalf("generateTrainingScript failed: %v", err)
	}

	// Verify script contains expected elements
	if !strings.Contains(script, "mlx-lm-lora") {
		t.Errorf("script does not contain mlx-lm-lora")
	}
	if !strings.Contains(script, "--train-mode dpo") {
		t.Errorf("script does not contain --train-mode dpo")
	}
	if !strings.Contains(script, "mlx-community/Mistral-7B-v0.1-4bit") {
		t.Errorf("script does not contain base model name")
	}
	if !strings.Contains(script, "/data/train.jsonl") {
		t.Errorf("script does not contain dataset path")
	}
	if !strings.Contains(script, "--export-gguf") {
		t.Errorf("script does not contain GGUF export")
	}
	if !strings.Contains(script, "#!/usr/bin/env bash") {
		t.Errorf("script does not contain bash shebang")
	}
}

func TestGenerateScript_UnknownBackend(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unknown-backend",
		Algorithm:   "dpo",
		BaseModel:   "some-model",
		DatasetPath: "/data/train.jsonl",
		OutputDir:   "/output",
	}

	_, err := generateTrainingScript(cfg)
	if err == nil {
		t.Errorf("expected error for unknown backend, got nil")
	}
	if !strings.Contains(err.Error(), "unknown backend") {
		t.Errorf("expected 'unknown backend' error, got: %v", err)
	}
}

func TestGenerateScript_UnknownAlgorithm_Unsloth(t *testing.T) {
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "invalid-algo",
		BaseModel:   "some-model",
		DatasetPath: "/data/train.jsonl",
		OutputDir:   "/output",
	}

	_, err := generateTrainingScript(cfg)
	if err == nil {
		t.Errorf("expected error for unknown algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "unknown algorithm") {
		t.Errorf("expected 'unknown algorithm' error, got: %v", err)
	}
}

func TestRun_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}

	// Create temp directory
	tmpDir := t.TempDir()
	scriptsDir := filepath.Join(tmpDir, "scripts")

	// Create a script that sleeps longer than timeout
	cfg := RunConfig{
		Backend:     "unsloth",
		Algorithm:   "sft",
		BaseModel:   "test-model",
		DatasetPath: filepath.Join(tmpDir, "test.jsonl"),
		OutputDir:   tmpDir,
		ScriptsDir:  scriptsDir,
		TimeoutSec:  1, // 1 second timeout
	}

	// Create dummy dataset file
	if err := os.WriteFile(cfg.DatasetPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to create test dataset: %v", err)
	}

	// Override script generation to create a sleep script
	origFunc := scriptGenerator
	scriptGenerator = func(c RunConfig) (string, error) {
		return `#!/usr/bin/env python3
import time
print("Sleeping...")
time.sleep(10)
print("Done sleeping")
`, nil
	}
	defer func() { scriptGenerator = origFunc }()

	ctx := context.Background()
	result, err := Run(ctx, cfg)

	// Expect error due to timeout
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}

	// Verify duration is roughly 1 second
	if result.Duration < 800*time.Millisecond || result.Duration > 2*time.Second {
		t.Errorf("expected duration ~1s, got %v", result.Duration)
	}

	// Verify non-zero exit code
	if result.ExitCode == 0 {
		t.Errorf("expected non-zero exit code for timeout, got 0")
	}
}

func TestFindGGUF(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "models")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// Create GGUF file
	ggufPath := filepath.Join(subDir, "model.gguf")
	if err := os.WriteFile(ggufPath, []byte("fake gguf"), 0644); err != nil {
		t.Fatalf("failed to create GGUF file: %v", err)
	}

	// Create some other files
	if err := os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("failed to create other file: %v", err)
	}

	// Test finding GGUF
	foundPath, err := findGGUF(tmpDir)
	if err != nil {
		t.Fatalf("findGGUF failed: %v", err)
	}

	if foundPath != ggufPath {
		t.Errorf("expected path %s, got %s", ggufPath, foundPath)
	}
}

func TestFindGGUF_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some non-GGUF files
	if err := os.WriteFile(filepath.Join(tmpDir, "model.bin"), []byte("data"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	_, err := findGGUF(tmpDir)
	if err == nil {
		t.Errorf("expected error when GGUF not found, got nil")
	}
	if !strings.Contains(err.Error(), "no .gguf file found") {
		t.Errorf("expected 'no .gguf file found' error, got: %v", err)
	}
}

func TestFindGGUF_CaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create GGUF file with uppercase extension
	ggufPath := filepath.Join(tmpDir, "MODEL.GGUF")
	if err := os.WriteFile(ggufPath, []byte("fake gguf"), 0644); err != nil {
		t.Fatalf("failed to create GGUF file: %v", err)
	}

	foundPath, err := findGGUF(tmpDir)
	if err != nil {
		t.Fatalf("findGGUF failed: %v", err)
	}

	if foundPath != ggufPath {
		t.Errorf("expected path %s, got %s", ggufPath, foundPath)
	}
}

func TestRun_MissingConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  RunConfig
		want string
	}{
		{
			name: "missing backend",
			cfg: RunConfig{
				Algorithm:   "sft",
				BaseModel:   "model",
				DatasetPath: "/data",
				OutputDir:   "/output",
			},
			want: "backend is required",
		},
		{
			name: "missing algorithm",
			cfg: RunConfig{
				Backend:     "unsloth",
				BaseModel:   "model",
				DatasetPath: "/data",
				OutputDir:   "/output",
			},
			want: "algorithm is required",
		},
		{
			name: "missing base model",
			cfg: RunConfig{
				Backend:     "unsloth",
				Algorithm:   "sft",
				DatasetPath: "/data",
				OutputDir:   "/output",
			},
			want: "base model is required",
		},
		{
			name: "missing dataset",
			cfg: RunConfig{
				Backend:   "unsloth",
				Algorithm: "sft",
				BaseModel: "model",
				OutputDir: "/output",
			},
			want: "dataset path is required",
		},
		{
			name: "missing output dir",
			cfg: RunConfig{
				Backend:     "unsloth",
				Algorithm:   "sft",
				BaseModel:   "model",
				DatasetPath: "/data",
			},
			want: "output directory is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.cfg)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected error containing %q, got: %v", tt.want, err)
			}
		})
	}
}
