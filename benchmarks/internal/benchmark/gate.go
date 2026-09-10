// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ValidateSmokePredictions turns the inert smoke corpus into a CI gate while
// leaving external public benchmarks non-gating. It checks dispositions and
// declared rule ownership without imposing benchmark labels on production.
func ValidateSmokePredictions(cases []Case, predictions []Prediction) error {
	caseByID := make(map[string]Case, len(cases))
	for _, benchmarkCase := range cases {
		caseByID[benchmarkCase.ID] = benchmarkCase
	}
	var failures []string
	for _, prediction := range predictions {
		benchmarkCase, ok := caseByID[prediction.CaseID]
		if !ok || benchmarkCase.Split != "smoke" || benchmarkCase.Truth.Applicability != InScope {
			continue
		}
		if prediction.ErrorCode != "" || prediction.Action == "error" {
			failures = append(failures, fmt.Sprintf("%s/%s: error=%s", prediction.Profile, prediction.CaseID, prediction.ErrorCode))
			continue
		}
		expectedAction := benchmarkCase.Truth.ExpectedProfileActions[prediction.Profile]
		if expectedAction == "" {
			switch benchmarkCase.Truth.ExpectedDisposition {
			case DispositionAllow:
				expectedAction = "allow"
			case DispositionDetectOnly:
				expectedAction = "alert"
			case DispositionBlock:
				expectedAction = "block"
			}
		}
		if prediction.Action != expectedAction {
			failures = append(failures, fmt.Sprintf("%s/%s: want action=%s, got detected=%t action=%s rules=%v", prediction.Profile, prediction.CaseID, expectedAction, prediction.Detected, prediction.Action, prediction.RuleIDs))
		}
		if benchmarkCase.Truth.ExpectedDisposition != DispositionAllow && !prediction.Detected {
			failures = append(failures, fmt.Sprintf("%s/%s: expected detection, got rules=%v", prediction.Profile, prediction.CaseID, prediction.RuleIDs))
		}
		if benchmarkCase.Truth.ExpectedDisposition != DispositionAllow {
			for _, expectedRuleID := range benchmarkCase.Truth.RuleIDs {
				if !slices.Contains(prediction.RuleIDs, expectedRuleID) {
					failures = append(failures, fmt.Sprintf("%s/%s: missing expected rule %s in %v", prediction.Profile, prediction.CaseID, expectedRuleID, prediction.RuleIDs))
				}
			}
		}
	}
	if len(failures) == 0 {
		return nil
	}
	sort.Strings(failures)
	return fmt.Errorf("benchmark smoke gate failed:\n  %s", strings.Join(failures, "\n  "))
}
