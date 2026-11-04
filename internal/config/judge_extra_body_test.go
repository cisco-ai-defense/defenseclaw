// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestJudgeExtraBodyLoadsNestedValues(t *testing.T) {
	cfg := loadLegacyConnectorFixture(t, `config_version: 9
guardrail:
  judge:
    extra_body:
      chat_template_kwargs:
        enable_thinking: false
        options: [one, two]
      reasoning_effort: none
      SamplerFlag: 2
`)
	kwargs, ok := cfg.Guardrail.Judge.ExtraBody["chat_template_kwargs"].(map[string]any)
	if !ok || kwargs["enable_thinking"] != false {
		t.Fatalf("nested extra_body = %#v", cfg.Guardrail.Judge.ExtraBody)
	}
	if cfg.Guardrail.Judge.ExtraBody["reasoning_effort"] != "none" {
		t.Fatalf("extra_body = %#v", cfg.Guardrail.Judge.ExtraBody)
	}
	if cfg.Guardrail.Judge.ExtraBody["SamplerFlag"] != 2 {
		t.Fatalf("case-sensitive extra_body key changed: %#v", cfg.Guardrail.Judge.ExtraBody)
	}

	plain := loadLegacyConnectorFixture(t, "config_version: 9\nguardrail:\n  judge: {}\n")
	if len(plain.Guardrail.Judge.ExtraBody) != 0 {
		t.Fatalf("unset extra_body = %#v, want empty", plain.Guardrail.Judge.ExtraBody)
	}
}

func TestJudgeExtraBodyRejectsReservedKeysAtConfigLoad(t *testing.T) {
	for _, key := range []string{
		"model", "Messages", "tools", "tool_choice", "stream", "max_tokens",
		"Max-Completion-Tokens", "response_format", "Authorization", "api_key",
		"access_token", "extra_headers", "base_url", "provider", "api_key_env", "target_url",
	} {
		t.Run(key, func(t *testing.T) {
			raw := []byte("config_version: 9\nguardrail:\n  judge:\n    extra_body:\n      " + key + ": value\n")
			err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("ValidateCandidate() = %v, want key %q named", err, key)
			}
		})
	}
}
