package routing

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTranslate_MinimalConfig(t *testing.T) {
	input := TranslateInput{
		Port: 8888,
		Models: []TranslateModel{
			{Name: "fast", Provider: "ollama", Model: "smollm2:1.7b", BaseURL: "http://127.0.0.1:11434"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "code_task", Keywords: []string{"code", "debug"}, Operator: "OR"},
			},
		},
		Decisions: []TranslateDecision{
			{Name: "default", Priority: 10, ModelRefs: []string{"fast"}},
		},
	}

	cfg := Translate(input)

	if cfg.Version != "v0.3" {
		t.Errorf("Version = %q, want v0.3", cfg.Version)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("Listeners count = %d, want 1", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Port != 8888 {
		t.Errorf("Listener port = %d, want 8888", cfg.Listeners[0].Port)
	}
	if cfg.Listeners[0].Address != "0.0.0.0" {
		t.Errorf("Listener address = %q, want 0.0.0.0", cfg.Listeners[0].Address)
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("Providers count = %d, want 1", len(cfg.Providers))
	}
	p, ok := cfg.Providers["fast"]
	if !ok {
		t.Fatal("Provider 'fast' not found")
	}
	if p.Model != "smollm2:1.7b" {
		t.Errorf("Provider model = %q, want smollm2:1.7b", p.Model)
	}
	if len(cfg.Routing.Signals.Keywords) != 1 {
		t.Fatalf("Keywords count = %d, want 1", len(cfg.Routing.Signals.Keywords))
	}
	if cfg.Routing.Signals.Keywords[0].Name != "code_task" {
		t.Errorf("Keyword name = %q, want code_task", cfg.Routing.Signals.Keywords[0].Name)
	}
	if len(cfg.Routing.Decisions) != 1 {
		t.Fatalf("Decisions count = %d, want 1", len(cfg.Routing.Decisions))
	}
}

func TestTranslate_DefaultPort(t *testing.T) {
	input := TranslateInput{
		Models: []TranslateModel{{Name: "m1", Provider: "x", Model: "x"}},
	}
	cfg := Translate(input)
	if cfg.Listeners[0].Port != 8888 {
		t.Errorf("Default port = %d, want 8888", cfg.Listeners[0].Port)
	}
}

func TestTranslate_MultipleProviders(t *testing.T) {
	input := TranslateInput{
		Port: 9000,
		Models: []TranslateModel{
			{Name: "reasoning", Provider: "anthropic", Model: "claude-sonnet-4-6", Capabilities: []string{"reasoning"}},
			{Name: "fast", Provider: "openai", Model: "gpt-4o-mini", CostPer1kTokens: 0.00015},
		},
	}
	cfg := Translate(input)
	if len(cfg.Providers) != 2 {
		t.Fatalf("Providers = %d, want 2", len(cfg.Providers))
	}
	if cfg.Providers["reasoning"].Provider != "anthropic" {
		t.Error("reasoning provider should be anthropic")
	}
	if cfg.Providers["fast"].CostPer1kTokens != 0.00015 {
		t.Error("fast cost should be 0.00015")
	}
}

func TestTranslate_SignalsUnderRouting(t *testing.T) {
	input := TranslateInput{
		Port:   8888,
		Models: []TranslateModel{{Name: "m1", Provider: "x", Model: "x"}},
		Signals: TranslateSignals{
			Keywords:           []TranslateKeyword{{Name: "test", Keywords: []string{"hello"}}},
			EmbeddingEnabled:   true,
			EmbeddingThreshold: 0.75,
			DomainEnabled:      true,
		},
	}
	cfg := Translate(input)
	if cfg.Routing.Signals.Embedding == nil || !cfg.Routing.Signals.Embedding.Enabled {
		t.Error("embedding signal should be enabled")
	}
	if cfg.Routing.Signals.Domain == nil || !cfg.Routing.Signals.Domain.Enabled {
		t.Error("domain signal should be enabled")
	}
}

func TestTranslateAndWrite_WritesFile(t *testing.T) {
	dir := t.TempDir()
	input := TranslateInput{
		Port:      8888,
		Models:    []TranslateModel{{Name: "m1", Provider: "ollama", Model: "x"}},
		Decisions: []TranslateDecision{{Name: "d1", Priority: 10, ModelRefs: []string{"m1"}}},
	}

	path, err := TranslateAndWrite(input, dir)
	if err != nil {
		t.Fatalf("TranslateAndWrite: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}

	var parsed SRConfig
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal written YAML: %v", err)
	}
	if parsed.Version != "v0.3" {
		t.Errorf("written version = %q, want v0.3", parsed.Version)
	}
}

func TestTranslateAndWrite_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	input := TranslateInput{
		Port:   8888,
		Models: []TranslateModel{{Name: "m1", Provider: "x", Model: "x"}},
	}

	_, err := TranslateAndWrite(input, dir)
	if err != nil {
		t.Fatalf("TranslateAndWrite: %v", err)
	}

	// .tmp should not linger
	tmp := filepath.Join(dir, "config.yaml.tmp")
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error(".tmp file should not exist after successful write")
	}
}
