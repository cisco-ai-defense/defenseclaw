package routing

import (
	"bytes"
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
	if len(cfg.Providers.Models) != 1 {
		t.Fatalf("Providers count = %d, want 1", len(cfg.Providers.Models))
	}
	p := cfg.Providers.Models[0]
	if p.Name != "fast" || p.ProviderModelID != "smollm2:1.7b" {
		t.Errorf("Provider model = %+v, want fast/smollm2:1.7b", p)
	}
	if cfg.Providers.Defaults.DefaultModel != "fast" {
		t.Errorf("default model = %q, want fast", cfg.Providers.Defaults.DefaultModel)
	}
	if len(cfg.Routing.ModelCards) != 1 || cfg.Routing.ModelCards[0].Name != "fast" {
		t.Fatalf("model cards = %+v, want fast", cfg.Routing.ModelCards)
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
	if cfg.Listeners[0].Port != DefaultAPIPort {
		t.Errorf("Default port = %d, want %d", cfg.Listeners[0].Port, DefaultAPIPort)
	}
}

func TestTranslate_MultipleProviders(t *testing.T) {
	input := TranslateInput{
		Port: 9000,
		Models: []TranslateModel{
			{Name: "reasoning", Provider: "anthropic", Model: "claude-sonnet-4-6", Capabilities: []string{"reasoning"}},
			{Name: "fast", Provider: "openai", Model: "gpt-4o-mini"},
		},
	}
	cfg := Translate(input)
	if len(cfg.Providers.Models) != 2 {
		t.Fatalf("Providers = %d, want 2", len(cfg.Providers.Models))
	}
	if cfg.Providers.Models[0].Name != "reasoning" || cfg.Providers.Models[0].ProviderModelID != "claude-sonnet-4-6" {
		t.Fatalf("first provider = %+v", cfg.Providers.Models[0])
	}
}

func TestTranslate_DisablesUnusedRouterServices(t *testing.T) {
	input := TranslateInput{
		Port:    8888,
		Models:  []TranslateModel{{Name: "m1", Provider: "x", Model: "x"}},
		Signals: TranslateSignals{Keywords: []TranslateKeyword{{Name: "test", Keywords: []string{"hello"}}}},
	}
	cfg := Translate(input)
	if cfg.Global.Services.ResponseAPI.Enabled || cfg.Global.Services.RouterReplay.Enabled ||
		cfg.Global.Services.Observability.Tracing.Enabled || cfg.Global.Services.Observability.Metrics.Enabled ||
		cfg.Global.Stores.SemanticCache.Enabled || cfg.Global.Router.ModelSelection.Enabled {
		t.Fatalf("classifier-only services were not disabled: %+v", cfg.Global)
	}
	if cfg.Global.ModelCatalog.Embeddings.Semantic.EmbeddingConfig.PreloadEmbeddings {
		t.Fatal("learned embedding preload must be disabled")
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
	if !bytes.Contains(data, []byte("conditions: []")) {
		t.Fatalf("unconditional fallback must emit canonical v0.3 conditions: []; config:\n%s", data)
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

func TestTranslateAndWrite_ReplacesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	first := TranslateInput{
		Port:   8080,
		Models: []TranslateModel{{Name: "first", Provider: "ollama", Model: "qwen2.5:0.5b"}},
	}
	if _, err := TranslateAndWrite(first, dir); err != nil {
		t.Fatalf("first TranslateAndWrite: %v", err)
	}

	second := TranslateInput{
		Port:   8081,
		Models: []TranslateModel{{Name: "second", Provider: "ollama", Model: "qwen3.5:9b-mlx"}},
	}
	path, err := TranslateAndWrite(second, dir)
	if err != nil {
		t.Fatalf("replacement TranslateAndWrite: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	var parsed SRConfig
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal replacement: %v", err)
	}
	if parsed.Listeners[0].Port != 8081 {
		t.Fatalf("replacement port = %d, want 8081", parsed.Listeners[0].Port)
	}
}
