// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// #1395: guardrail.judge.max_parallel bounds the judge calls sent to the
// judge model at once. It is off (0) unless set, and the schema refuses a
// negative bound.
func TestJudgeMaxParallelLoadsAndDefaultsOff(t *testing.T) {
	cfg := loadLegacyConnectorFixture(t, "config_version: 9\nguardrail:\n  judge:\n    enabled: true\n    max_parallel: 2\n")
	if cfg.Guardrail.Judge.MaxParallel != 2 {
		t.Fatalf("max_parallel = %d, want 2", cfg.Guardrail.Judge.MaxParallel)
	}
	cfg = loadLegacyConnectorFixture(t, "config_version: 9\nguardrail:\n  judge:\n    enabled: true\n")
	if cfg.Guardrail.Judge.MaxParallel != 0 {
		t.Fatalf("max_parallel default = %d, want 0 (no limit)", cfg.Guardrail.Judge.MaxParallel)
	}
}

func TestJudgeMaxParallelSchemaRefusesNegativeAndText(t *testing.T) {
	for _, value := range []string{"-1", "two"} {
		raw := []byte("config_version: 9\nguardrail:\n  judge:\n    max_parallel: " + value + "\n")
		err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw)
		if err == nil || !strings.Contains(err.Error(), "max_parallel") {
			t.Fatalf("max_parallel %s: ValidateCandidate() error = %v, want a max_parallel refusal", value, err)
		}
	}
	raw := []byte("config_version: 9\nguardrail:\n  judge:\n    max_parallel: 4\n")
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
		t.Fatalf("max_parallel 4: ValidateCandidate() error = %v", err)
	}
}
