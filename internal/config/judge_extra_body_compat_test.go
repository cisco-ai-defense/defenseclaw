// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"testing"
)

func TestJudgeExtraBodySchemaAcceptsNestedMap(t *testing.T) {
	raw := []byte(`config_version: 9
guardrail:
  judge:
    extra_body:
      chat_template_kwargs:
        enable_thinking: false
`)
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
		t.Fatalf("nested judge extra_body: %v", err)
	}
}

func TestJudgeExtraBodySchemaBenignTwin(t *testing.T) {
	raw := []byte(`config_version: 9
guardrail:
  judge:
    max_parallel: 1
`)
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
		t.Fatalf("ordinary judge config: %v", err)
	}
}
