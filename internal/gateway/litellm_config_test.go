package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestLiteLLMProviderPrefix(t *testing.T) {
	tests := []struct {
		baseURL string
		want    string
	}{
		{"https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6", "deepseek"},
		{"https://api.ollama.com", "ollama"},
		{"https://api.anthropic.com", "anthropic"},
		{"https://api.openai.com/v1", "openai"},
		{"http://localhost:11434", "openai"},
	}
	for _, tt := range tests {
		got := litellmProviderPrefix(tt.baseURL)
		if got != tt.want {
			t.Errorf("litellmProviderPrefix(%q) = %q, want %q", tt.baseURL, got, tt.want)
		}
	}
}

func TestTranslateLiteLLMModel_CircuitAPI(t *testing.T) {
	model := config.RoutingModelBackend{
		Name:      "claude-sonnet",
		Provider:  "azure",
		Model:     "claude-sonnet-4-6",
		BaseURL:   "https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6",
		APIKeyEnv: "CISCO_AI_JWT",
	}
	t.Setenv("CISCO_AI_JWT", "test-jwt-token")

	params := TranslateLiteLLMModel(model, "")
	if params.ModelName != "claude-sonnet" {
		t.Errorf("ModelName = %q, want %q", params.ModelName, "claude-sonnet")
	}
	if params.LiteLLMParams.Model != "deepseek/claude-sonnet-4-6" {
		t.Errorf("Model = %q, want %q", params.LiteLLMParams.Model, "deepseek/claude-sonnet-4-6")
	}
	if params.LiteLLMParams.ExtraHeaders["api-key"] != "test-jwt-token" {
		t.Errorf("api-key header = %q, want %q", params.LiteLLMParams.ExtraHeaders["api-key"], "test-jwt-token")
	}
}

func TestTranslateLiteLLMModel_Ollama(t *testing.T) {
	model := config.RoutingModelBackend{
		Name:    "ollama-glm",
		Model:   "glm-5.3",
		BaseURL: "https://api.ollama.com",
	}
	params := TranslateLiteLLMModel(model, "")
	if params.LiteLLMParams.Model != "ollama/glm-5.3" {
		t.Errorf("Model = %q, want %q", params.LiteLLMParams.Model, "ollama/glm-5.3")
	}
}

func TestTranslateLiteLLMModels_IncludesWildcard(t *testing.T) {
	cfg := &config.Config{}
	cfg.LLM.Provider = "azure"
	cfg.LLM.Model = "claude-sonnet-4-6"
	cfg.LLM.BaseURL = "https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6"
	cfg.LLM.APIKeyEnv = "CISCO_AI_JWT"
	cfg.Routing.Models = []config.RoutingModelBackend{
		{Name: "gpt-nano", Model: "gpt-5-4-nano", BaseURL: "https://chat-ai.cisco.com/openai/deployments/gpt-5-4-nano", APIKeyEnv: "CISCO_AI_JWT"},
	}
	t.Setenv("CISCO_AI_JWT", "test-jwt")

	models := TranslateLiteLLMModels(cfg)
	// default + gpt-nano + wildcard = 3
	if len(models) != 3 {
		t.Fatalf("got %d models, want 3", len(models))
	}
	if models[0].ModelName != "default" {
		t.Errorf("first model = %q, want %q", models[0].ModelName, "default")
	}
	if models[len(models)-1].ModelName != "*" {
		t.Errorf("last model = %q, want %q", models[len(models)-1].ModelName, "*")
	}
}
