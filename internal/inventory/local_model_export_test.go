// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

var localModelKeyPattern = regexp.MustCompile(`^mdl_[0-9a-f]{64}$`)

func TestLocalModelKeyIsStableAndShapeChecked(t *testing.T) {
	sum := sha256.Sum256([]byte("ai-discovery/model-key/v1\x00ollama\x00llama3.2:3b"))
	want := "mdl_" + hex.EncodeToString(sum[:])
	if got := LocalModelKey("ollama", "llama3.2:3b"); got != want {
		t.Fatalf("LocalModelKey=%q want %q", got, want)
	}
	if !localModelKeyPattern.MatchString(want) {
		t.Fatalf("key %q does not match the registry pattern", want)
	}
}

func TestLocalModelKeySameModelFromFileAndAPI(t *testing.T) {
	// An Ollama manifest yields provider "ollama" and ID "llama3.2:3b"; the
	// loopback /api/tags probe yields the catalog provider key "ollama" and the
	// same model ID. Both must collapse to one key.
	fileKey := LocalModelKey("ollama", "llama3.2:3b")
	apiKey := LocalModelKey(" Ollama ", "llama3.2:3b ")
	if fileKey == "" || fileKey != apiKey {
		t.Fatalf("file key %q != api key %q", fileKey, apiKey)
	}
	if LocalModelKey("lmstudio", "llama3.2:3b") == fileKey {
		t.Fatal("a different runtime must give a different key")
	}
	if LocalModelKey("lm-studio", "x") != LocalModelKey("lmstudio", "x") {
		t.Fatal("provider spellings must normalize before hashing")
	}
}

func TestLocalModelKeyEmptyOrInvalidID(t *testing.T) {
	for _, id := range []string{"", "   ", "bad\nid", "bad\x00id"} {
		if got := LocalModelKey("ollama", id); got != "" {
			t.Fatalf("LocalModelKey(%q)=%q want empty", id, got)
		}
	}
}

func TestLocalModelExportIDCapsAtRuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 400) // 800 bytes
	got := LocalModelExportID(long)
	if len(got) > 512 || !strings.HasPrefix(long, got) || len(got)%2 != 0 {
		t.Fatalf("export id len=%d not capped on a rune boundary", len(got))
	}
}

func TestLocalModelKeyHashesTheCompleteID(t *testing.T) {
	prefix := strings.Repeat("a", 512)
	first, second := LocalModelKey("huggingface", prefix+"-one"), LocalModelKey("huggingface", prefix+"-two")
	if first == "" || first == second {
		t.Fatalf("IDs that differ past the export cap share key %q", first)
	}
	if LocalModelExportID(prefix+"-one") != LocalModelExportID(prefix+"-two") {
		t.Fatal("the exported ID is still capped at 512 bytes")
	}
	sum := sha256.Sum256([]byte("ai-discovery/model-key/v1\x00huggingface\x00" + prefix + "-one"))
	if want := "mdl_" + hex.EncodeToString(sum[:]); first != want {
		t.Fatalf("LocalModelKey=%q want the hash of the complete ID %q", first, want)
	}
}

func TestNormalizeLocalModelProvider(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"ollama":          "ollama",
		"LMStudio":        "lmstudio",
		"lm-studio":       "lmstudio",
		"huggingface":     "huggingface",
		"mlx":             "mlx",
		"llamacpp":        "llamacpp",
		"lemonade-server": "lemonade",
		"localai":         "localai",
		"vllm":            "vllm",
		"flm":             "flm",
		"filesystem":      "filesystem",
		"coreml":          "coreml",
		"something-new":   "other",
	}
	for in, want := range cases {
		if got := NormalizeLocalModelProvider(in); got != want {
			t.Errorf("NormalizeLocalModelProvider(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeLocalModelFormatModalityRelevanceStatus(t *testing.T) {
	formats := map[string]string{
		"": "", "GGUF": "gguf", ".safetensors": "safetensors", "pt": "pytorch", "pth": "pytorch",
		"ckpt": "pytorch", "bin": "bin", "ollama": "ollama", "ollama-blob": "ollama-blob",
		"mlmodel": "coreml", "coreml": "coreml", "weird": "other",
	}
	for in, want := range formats {
		if got := NormalizeLocalModelFormat(in); got != want {
			t.Errorf("NormalizeLocalModelFormat(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "", "generative": "generative", "Speech": "speech", "text": "unknown"} {
		if got := NormalizeLocalModelModality(in); got != want {
			t.Errorf("NormalizeLocalModelModality(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "", "embedded": "embedded", "PRIMARY": "primary", "x": "unknown"} {
		if got := NormalizeLocalModelRelevance(in); got != want {
			t.Errorf("NormalizeLocalModelRelevance(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"installed": "installed", "Loaded": "loaded", "running": "", "": ""} {
		if got := NormalizeLocalModelStatus(in); got != want {
			t.Errorf("NormalizeLocalModelStatus(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLocalModelExportOwnerRejectsPaths(t *testing.T) {
	if got := LocalModelExportOwner("LM Studio"); got != "LM Studio" {
		t.Fatalf("owner=%q", got)
	}
	for _, bad := range []string{"/Applications/X.app", `C:\Users\x`, "a\nb", ""} {
		if got := LocalModelExportOwner(bad); got != "" {
			t.Fatalf("LocalModelExportOwner(%q)=%q want empty", bad, got)
		}
	}
}
