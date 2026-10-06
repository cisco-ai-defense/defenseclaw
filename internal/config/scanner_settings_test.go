// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestScannersValidateCrossFieldRules(t *testing.T) {
	cases := map[string]ScannersConfig{
		"review above gate":      {SkillScanner: SkillScannerConfig{FailOnSeverity: "MEDIUM", ReviewQueueMin: "HIGH"}},
		"custom without digest":  {SkillScanner: SkillScannerConfig{Policy: "custom", PolicyFile: AssetFileRef{Path: "/p.yaml"}}},
		"override without model": {SkillScanner: SkillScannerConfig{JudgeSource: ScannerJudgeOverride}},
		"inherit with a block":   {MCPScanner: MCPScannerConfig{JudgeSource: ScannerJudgeInherit, LLM: LLMConfig{Model: "m"}}},
	}
	for name, cfg := range cases {
		err := cfg.Validate()
		var semantic *V8SemanticError
		if !errors.As(err, &semantic) || !strings.HasPrefix(semantic.Path, "$.scanners.") || semantic.Summary == "" {
			t.Errorf("%s: Validate() = %v, want a *V8SemanticError at a $.scanners key (GAP-0128)", name, err)
		}
	}
	if err := (ScannersConfig{}).Validate(); err != nil {
		t.Errorf("defaults: %v", err)
	}
}
