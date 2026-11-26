// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// The values below are the closed vocabularies of the defenseclaw.ai.model.*
// telemetry attributes. Only the Secure Client profile sends them (Spec 016):
// the managed AI Defense destination uses them to keep one inventory row per
// device and model.

const (
	localModelKeyPrefix      = "mdl_"
	localModelKeyDomain      = "ai-discovery/model-key/v1"
	maxExportedModelIDBytes  = 512
	maxExportedModelOwnBytes = 128

	// LocalModelExportProviderOther, LocalModelExportFormatOther and
	// LocalModelExportUnknown are the fallbacks for a value outside a closed set.
	LocalModelExportProviderOther = "other"
	LocalModelExportFormatOther   = "other"
	LocalModelExportUnknown       = "unknown"
)

// localModelExportProviders maps every provider spelling the scanner and the
// loopback model APIs produce to the exported vocabulary.
var localModelExportProviders = map[string]string{
	"ollama":          "ollama",
	"lmstudio":        "lmstudio",
	"lm-studio":       "lmstudio",
	"huggingface":     "huggingface",
	"hugging-face":    "huggingface",
	"mlx":             "mlx",
	"llamacpp":        "llamacpp",
	"llama.cpp":       "llamacpp",
	"llama-cpp":       "llamacpp",
	"lemonade":        "lemonade",
	"lemonade-server": "lemonade",
	"jan":             "jan",
	"gpt4all":         "gpt4all",
	"anythingllm":     "anythingllm",
	"localai":         "localai",
	"vllm":            "vllm",
	"coreml":          "coreml",
	"flm":             "flm",
	"filesystem":      "filesystem",
}

// localModelExportFormats maps scanner and API format spellings to the
// exported vocabulary. "ollama" is an Ollama manifest; "ollama-blob" is the
// Ollama blob store aggregate, which is not a model and which AI Defense skips.
var localModelExportFormats = map[string]string{
	"gguf":        "gguf",
	"ggml":        "ggml",
	"safetensors": "safetensors",
	"mlx":         "mlx",
	"coreml":      "coreml",
	"mlmodel":     "coreml",
	"mlpackage":   "coreml",
	"mlmodelc":    "coreml",
	"q4nx":        "q4nx",
	"onnx":        "onnx",
	"ort":         "ort",
	"tflite":      "tflite",
	"pt":          "pytorch",
	"pth":         "pytorch",
	"ckpt":        "pytorch",
	"pytorch":     "pytorch",
	"bin":         "bin",
	"ollama":      "ollama",
	"ollama-blob": "ollama-blob",
}

var localModelExportModalities = map[string]struct{}{
	localModelModalityGenerative: {},
	localModelModalitySpeech:     {},
	localModelModalityVision:     {},
	localModelModalityEmbedding:  {},
	localModelModalityAudio:      {},
	localModelModalityUnknown:    {},
}

var localModelExportRelevances = map[string]struct{}{
	localModelRelevancePrimary:    {},
	localModelRelevanceSupporting: {},
	localModelRelevanceEmbedded:   {},
	localModelRelevanceUnknown:    {},
}

// NormalizeLocalModelProvider returns the exported provider for a scanner or
// API provider value. An empty value stays empty; an unlisted one is "other".
func NormalizeLocalModelProvider(provider string) string {
	value := strings.ToLower(strings.TrimSpace(provider))
	if value == "" {
		return ""
	}
	if exported, ok := localModelExportProviders[value]; ok {
		return exported
	}
	return LocalModelExportProviderOther
}

// NormalizeLocalModelFormat returns the exported format. An empty value stays
// empty; an unlisted one is "other".
func NormalizeLocalModelFormat(format string) string {
	value := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(format)), ".")
	if value == "" {
		return ""
	}
	if exported, ok := localModelExportFormats[value]; ok {
		return exported
	}
	return LocalModelExportFormatOther
}

// NormalizeLocalModelModality returns the exported modality: empty stays empty
// and an unlisted value is "unknown".
func NormalizeLocalModelModality(modality string) string {
	value := strings.ToLower(strings.TrimSpace(modality))
	if value == "" {
		return ""
	}
	if _, ok := localModelExportModalities[value]; ok {
		return value
	}
	return LocalModelExportUnknown
}

// NormalizeLocalModelRelevance returns the exported relevance: empty stays
// empty and an unlisted value is "unknown".
func NormalizeLocalModelRelevance(relevance string) string {
	value := strings.ToLower(strings.TrimSpace(relevance))
	if value == "" {
		return ""
	}
	if _, ok := localModelExportRelevances[value]; ok {
		return value
	}
	return LocalModelExportUnknown
}

// NormalizeLocalModelStatus returns "installed" or "loaded", or empty for any
// other value.
func NormalizeLocalModelStatus(status string) string {
	switch value := strings.ToLower(strings.TrimSpace(status)); value {
	case "installed", "loaded":
		return value
	default:
		return ""
	}
}

// validLocalModelID trims the model ID and rejects invalid UTF-8 and control
// characters. It returns the complete ID, uncapped, or empty.
func validLocalModelID(id string) string {
	value := strings.TrimSpace(id)
	if value == "" || !utf8.ValidString(value) {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ""
		}
	}
	return value
}

// normalizeLocalModelExportID returns the valid model ID capped at 512 bytes
// on a rune boundary for export, or empty when nothing usable remains.
func normalizeLocalModelExportID(id string) string {
	return truncateUTF8(validLocalModelID(id), maxExportedModelIDBytes)
}

// LocalModelExportID returns the model ID as it is exported, or empty.
func LocalModelExportID(id string) string { return normalizeLocalModelExportID(id) }

// LocalModelExportOwner returns the owner application bounded to 128 bytes, or
// empty when it carries control characters or a path separator.
func LocalModelExportOwner(owner string) string {
	value := strings.TrimSpace(owner)
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, `/\`) {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ""
		}
	}
	return truncateUTF8(value, maxExportedModelOwnBytes)
}

// LocalModelKey returns the stable per-model key: "mdl_" plus the hex SHA-256
// of a versioned label, the normalized provider and the model ID. It depends
// on neither a path nor the gateway token, so a moved model, a reinstall or a
// purge keeps the key, and the same model found by a file and by a loopback
// API gets one key. The hash covers the complete ID, not the 512-byte export
// cap, so IDs that differ only past the cap get different keys. It returns
// empty when the model ID is empty.
func LocalModelKey(provider, id string) string {
	modelID := validLocalModelID(id)
	if modelID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(localModelKeyDomain + "\x00" + NormalizeLocalModelProvider(provider) + "\x00" + modelID))
	return localModelKeyPrefix + hex.EncodeToString(sum[:])
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
