// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
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
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "scanners.") {
			t.Errorf("%s: Validate() = %v, want a scanners error", name, err)
		}
	}
	if err := (ScannersConfig{}).Validate(); err != nil {
		t.Errorf("defaults: %v", err)
	}
}
