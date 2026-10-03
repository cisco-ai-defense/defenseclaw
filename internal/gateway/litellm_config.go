// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// LiteLLMModelParams is the payload for POST /model/new on the LiteLLM proxy.
type LiteLLMModelParams struct {
	ModelName     string                `json:"model_name"`
	LiteLLMParams LiteLLMProviderParams `json:"litellm_params"`
	ModelInfo     map[string]interface{} `json:"model_info,omitempty"`
}

// LiteLLMProviderParams are the provider-specific fields for a LiteLLM model.
type LiteLLMProviderParams struct {
	Model        string            `json:"model"`
	APIBase      string            `json:"api_base,omitempty"`
	APIKey       string            `json:"api_key,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// litellmProviderPrefix determines the LiteLLM provider prefix based on the
// upstream base URL. The prefix controls which LiteLLM adapter handles the
// request and whether the Responses→Chat bridge activates.
//
//   - "deepseek" for Circuit API (chat-ai.cisco.com): bridges Responses→Chat,
//     appends /chat/completions without /v1 prefix.
//   - "ollama" for Ollama Cloud: native ollama protocol.
//   - "anthropic" for Anthropic direct.
//   - "openai" for everything else.
func litellmProviderPrefix(baseURL string) string {
	lower := strings.ToLower(baseURL)
	switch {
	case strings.Contains(lower, "chat-ai.cisco.com"):
		return "deepseek"
	case strings.Contains(lower, "api.ollama.com"):
		return "ollama"
	case strings.Contains(lower, "api.anthropic.com"):
		return "anthropic"
	default:
		return "openai"
	}
}

// TranslateLiteLLMModel converts a DefenseClaw routing model into a LiteLLM
// model registration payload. The provider prefix, API key, and extra headers
// are resolved from the model's config and environment.
func TranslateLiteLLMModel(model config.RoutingModelBackend, dotenvPath string) LiteLLMModelParams {
	prefix := litellmProviderPrefix(model.BaseURL)
	apiKey := resolveKeyForLiteLLM(model.APIKeyEnv, dotenvPath)

	extraHeaders := make(map[string]string)
	if prefix == "deepseek" {
		extraHeaders["api-key"] = apiKey
	}
	if prefix == "ollama" {
		extraHeaders["Authorization"] = "Bearer " + apiKey
	}

	// Carry over extra_headers from the LLM config if present.
	// The appkey header for Circuit API is set here.
	if prefix == "deepseek" {
		extraHeaders["user"] = `{"appkey":"egai-prd-other-020122827-other-1790804579247","prompt_truncate":"no"}`
	}

	return LiteLLMModelParams{
		ModelName: model.Name,
		LiteLLMParams: LiteLLMProviderParams{
			Model:        prefix + "/" + model.Model,
			APIBase:      model.BaseURL,
			APIKey:       apiKey,
			ExtraHeaders: extraHeaders,
		},
	}
}

// TranslateLiteLLMModels converts all models from the DefenseClaw config into
// LiteLLM model registration payloads. It includes the main LLM model, all
// routing models, and a wildcard catch-all.
func TranslateLiteLLMModels(cfg *config.Config) []LiteLLMModelParams {
	dotenvPath := ""
	if cfg.DataDir != "" {
		dotenvPath = cfg.DataDir + "/.env"
	}

	var models []LiteLLMModelParams

	// Main LLM model as the default
	mainModel := config.RoutingModelBackend{
		Name:      "default",
		Provider:  cfg.LLM.Provider,
		Model:     cfg.LLM.Model,
		BaseURL:   cfg.LLM.BaseURL,
		APIKeyEnv: cfg.LLM.APIKeyEnv,
	}
	models = append(models, TranslateLiteLLMModel(mainModel, dotenvPath))

	// Routing models
	for _, m := range cfg.Routing.Models {
		models = append(models, TranslateLiteLLMModel(m, dotenvPath))
	}

	// Wildcard: unknown model names → main LLM model
	if len(models) > 0 {
		wildcard := models[0]
		wildcard.ModelName = "*"
		models = append(models, wildcard)
	}

	return models
}

func resolveKeyForLiteLLM(envVar string, dotenvPath string) string {
	if envVar == "" {
		return ""
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return ResolveAPIKey(envVar, dotenvPath)
}
