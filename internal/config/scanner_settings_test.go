// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// With admission.skill.actions unset, the action map is derived from the
// scanner gate: HIGH+ quarantines, [MEDIUM, HIGH) warns, below is allowed.
func TestSkillScannerDerivedAdmissionActionsFollowTheGate(t *testing.T) {
	got := SkillScannerConfig{}.DerivedAdmissionActions()
	want := map[string]string{"critical": "quarantine", "high": "quarantine", "medium": "warn", "low": "allow", "info": "allow"}
	for sev, action := range map[string]*AdmissionAction{
		"critical": got.Critical, "high": got.High, "medium": got.Medium, "low": got.Low, "info": got.Info,
	} {
		if action == nil || action.Shorthand != want[sev] {
			t.Errorf("%s = %+v, want %s", sev, action, want[sev])
		}
	}
}

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
