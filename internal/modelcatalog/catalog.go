package modelcatalog

import "github.com/defenseclaw/defenseclaw/internal/hwprofile"

// LocalModel represents a locally runnable model with hardware requirements.
type LocalModel struct {
	Name       string   `json:"name"`
	ParamsB    float64  `json:"params_b"`
	FP16GB     float64  `json:"fp16_gb"`
	INT4GB     float64  `json:"int4_gb"`
	ContextLen string   `json:"context_len"`
	License    string   `json:"license"`
	Quality    string   `json:"quality"`
	UseCases   []string `json:"use_cases"`
	OllamaTag  string   `json:"ollama_tag"`
}

// CloudModel represents a cloud-hosted model with pricing.
type CloudModel struct {
	Name       string   `json:"name"`
	Provider   string   `json:"provider"`
	ModelID    string   `json:"model_id"`
	InputCost  float64  `json:"input_cost"` // $/MTok
	OutputCost float64  `json:"output_cost"`
	UseCases   []string `json:"use_cases"`
	Tier       string   `json:"tier"` // "budget", "optimal"
}

// FitsHardware checks if a model can run on the given hardware profile.
func (m LocalModel) FitsHardware(profile *hwprofile.SystemProfile, quant string) bool {
	var requiredGB float64
	switch quant {
	case "FP16":
		requiredGB = m.FP16GB
	default:
		requiredGB = m.INT4GB
	}
	var availableGB float64
	if profile.UnifiedMemory {
		availableGB = profile.TotalRAMGB * 0.75
	} else if profile.HasGPU {
		availableGB = profile.TotalGPUVRAMGB
	} else {
		availableGB = profile.TotalRAMGB * 0.6
	}
	return requiredGB <= availableGB
}

// Top local models per use case — curated subset from the research survey.
var LocalCatalog = []LocalModel{
	// Coding
	{Name: "Qwen 2.5 Coder 7B", ParamsB: 7, FP16GB: 14, INT4GB: 4.5, ContextLen: "32k", License: "Apache 2.0", Quality: "Best coding model under 8B", UseCases: []string{"coding"}, OllamaTag: "qwen2.5-coder:7b"},
	{Name: "Qwen 2.5 Coder 32B", ParamsB: 32, FP16GB: 64, INT4GB: 18, ContextLen: "32k", License: "Apache 2.0", Quality: "Frontier-level coding", UseCases: []string{"coding"}, OllamaTag: "qwen2.5-coder:32b"},
	{Name: "DeepSeek Coder V2 Lite", ParamsB: 16, FP16GB: 32, INT4GB: 10, ContextLen: "128k", License: "DeepSeek", Quality: "Strong coding + long context", UseCases: []string{"coding"}, OllamaTag: "deepseek-coder-v2:16b"},
	// General reasoning
	{Name: "Qwen 3 8B", ParamsB: 8, FP16GB: 16, INT4GB: 5, ContextLen: "32k", License: "Apache 2.0", Quality: "Best general model under 10B", UseCases: []string{"general_reasoning", "coding"}, OllamaTag: "qwen3:8b"},
	{Name: "Llama 3.3 70B", ParamsB: 70, FP16GB: 140, INT4GB: 40, ContextLen: "128k", License: "Llama 3.3", Quality: "Frontier-level reasoning", UseCases: []string{"general_reasoning", "coding", "research_writing"}, OllamaTag: "llama3.3:70b"},
	{Name: "Phi-4 Mini 3.8B", ParamsB: 3.8, FP16GB: 7.6, INT4GB: 2.5, ContextLen: "16k", License: "MIT", Quality: "Excellent for edge/laptop", UseCases: []string{"general_reasoning"}, OllamaTag: "phi4-mini"},
	// Security
	{Name: "Llama Guard 3 8B", ParamsB: 8, FP16GB: 16, INT4GB: 5, ContextLen: "4k", License: "Llama 3.1", Quality: "Purpose-built content safety", UseCases: []string{"security"}, OllamaTag: "llama-guard3:8b"},
	{Name: "Qwen 3 4B", ParamsB: 4, FP16GB: 8, INT4GB: 2.5, ContextLen: "32k", License: "Apache 2.0", Quality: "Fast security classifier", UseCases: []string{"security", "general_reasoning"}, OllamaTag: "qwen3:4b"},
	// Data analysis
	{Name: "Qwen 2.5 72B", ParamsB: 72, FP16GB: 144, INT4GB: 42, ContextLen: "128k", License: "Qwen", Quality: "Strong analytical model", UseCases: []string{"data_analysis", "general_reasoning"}, OllamaTag: "qwen2.5:72b"},
	// Multimodal
	{Name: "Llava 1.6 7B", ParamsB: 7, FP16GB: 14, INT4GB: 4.5, ContextLen: "4k", License: "Apache 2.0", Quality: "Vision + text", UseCases: []string{"multimodal"}, OllamaTag: "llava:7b"},
}

// Top cloud models per use case.
var CloudCatalog = []CloudModel{
	// Coding
	{Name: "Claude Sonnet 4.6", Provider: "anthropic", ModelID: "claude-sonnet-4-6", InputCost: 3.0, OutputCost: 15.0, UseCases: []string{"coding", "general_reasoning"}, Tier: "optimal"},
	{Name: "GPT-5.5", Provider: "openai", ModelID: "gpt-5-5", InputCost: 2.0, OutputCost: 8.0, UseCases: []string{"coding", "general_reasoning"}, Tier: "optimal"},
	{Name: "GPT-5.4 Nano", Provider: "openai", ModelID: "gpt-5-4-nano", InputCost: 0.1, OutputCost: 0.4, UseCases: []string{"coding"}, Tier: "budget"},
	// General reasoning
	{Name: "Claude Opus 4.8", Provider: "anthropic", ModelID: "claude-opus-4-8", InputCost: 15.0, OutputCost: 75.0, UseCases: []string{"general_reasoning", "research_writing"}, Tier: "optimal"},
	{Name: "Gemini 3.5 Flash", Provider: "google", ModelID: "gemini-3.5-flash", InputCost: 0.075, OutputCost: 0.3, UseCases: []string{"general_reasoning", "data_analysis"}, Tier: "budget"},
	// Security
	{Name: "Claude Sonnet 4.6 (Security)", Provider: "anthropic", ModelID: "claude-sonnet-4-6", InputCost: 3.0, OutputCost: 15.0, UseCases: []string{"security"}, Tier: "optimal"},
}
