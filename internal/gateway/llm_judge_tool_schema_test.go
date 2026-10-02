// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Anthropic's rule for tool input_schema property keys. Bifrost sends the
// judge's response_format to Bedrock as a tool, so every key must match it.
var anthropicToolPropertyKeyRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

func collectSchemaPropertyKeys(t *testing.T, node interface{}, keys *[]string) {
	t.Helper()
	switch v := node.(type) {
	case map[string]interface{}:
		if props, ok := v["properties"].(map[string]interface{}); ok {
			for key, child := range props {
				*keys = append(*keys, key)
				collectSchemaPropertyKeys(t, child, keys)
			}
		}
		if items, ok := v["items"]; ok {
			collectSchemaPropertyKeys(t, items, keys)
		}
	case []interface{}:
		for _, child := range v {
			collectSchemaPropertyKeys(t, child, keys)
		}
	}
}

func TestJudgeBedrockSchemaKeysAreToolSafe(t *testing.T) {
	bedrock := &LLMJudge{
		cfg:          &config.JudgeConfig{},
		providerName: "bedrock",
		model:        "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
	}
	openai := &LLMJudge{cfg: &config.JudgeConfig{}, providerName: "openai", model: "openai/gpt-4o"}
	for _, kind := range []string{"injection", "pii", "exfil", "tool_injection", "adjudicate_pii"} {
		req := bedrock.judgeChatRequest([]ChatMessage{{Role: "user", Content: "sample"}}, 256, kind)
		var envelope struct {
			JSONSchema struct {
				Schema map[string]interface{} `json:"schema"`
			} `json:"json_schema"`
		}
		if err := json.Unmarshal(req.ResponseFormat, &envelope); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		var keys []string
		collectSchemaPropertyKeys(t, envelope.JSONSchema.Schema, &keys)
		if len(keys) == 0 {
			t.Fatalf("%s: schema has no properties", kind)
		}
		for _, key := range keys {
			if !anthropicToolPropertyKeyRe.MatchString(key) {
				t.Errorf("%s: Bedrock schema key %q breaks the tool key pattern", kind, key)
			}
		}
		// Providers without the tool translation keep the pinned schema.
		other := openai.judgeChatRequest([]ChatMessage{{Role: "user", Content: "sample"}}, 256, kind)
		if !bytes.Equal(other.ResponseFormat, judgeResponseFormat(kind)) {
			t.Errorf("%s: openai response_format changed", kind)
		}
	}
}

func TestParseJudgeJSONRestoresToolSafeCategoryKeys(t *testing.T) {
	got := parseJudgeJSON(`{"Instruction_Manipulation":{"reasoning":"r","label":true,"signal_strength":"strong_signal"},` +
		`"Driver_s_License_Number":{"detection_result":false,"entities":[]},"findings":[]}`)
	if _, ok := got["Instruction Manipulation"].(map[string]interface{}); !ok {
		t.Fatalf("injection category not restored: %#v", got)
	}
	if _, ok := got["Driver's License Number"].(map[string]interface{}); !ok {
		t.Fatalf("pii category not restored: %#v", got)
	}
	if _, ok := got["Instruction_Manipulation"]; ok {
		t.Fatalf("tool-safe key left behind: %#v", got)
	}
	if _, ok := got["findings"]; !ok {
		t.Fatalf("non-category key dropped: %#v", got)
	}
	verdict := (&LLMJudge{}).injectionToVerdict(got)
	if verdict == nil || verdict.Action == "allow" {
		t.Fatalf("restored injection label was not judged: %#v", verdict)
	}
}
