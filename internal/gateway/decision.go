// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	guardrailActionAllow   = "allow"
	guardrailActionAlert   = "alert"
	guardrailActionConfirm = "confirm"
	guardrailActionBlock   = "block"
)

const (
	severityNone = iota
	severityLow
	severityMedium
	severityHigh
	severityCritical
)

func guardrailRuntimeAction(cfg *config.Config, severity string, confirmable bool) string {
	if cfg == nil {
		return guardrailRuntimeActionForGuardrail(nil, severity, confirmable)
	}
	return guardrailRuntimeActionForGuardrail(&cfg.Guardrail, severity, confirmable)
}

func guardrailRuntimeActionForGuardrail(gc *config.GuardrailConfig, severity string, confirmable bool) string {
	rank := guardrailSeverityRank(severity)
	if rank <= severityNone {
		return guardrailActionAllow
	}

	blockThreshold, alertThreshold := guardrailThresholds(gc)
	if rank >= blockThreshold {
		return guardrailActionBlock
	}
	if hiltEnabled(gc) && confirmable && rank >= hiltMinRank(gc) {
		return guardrailActionConfirm
	}
	if rank >= alertThreshold {
		return guardrailActionAlert
	}
	return guardrailActionAllow
}

func guardrailThresholds(gc *config.GuardrailConfig) (blockThreshold int, alertThreshold int) {
	switch guardrailProfile(gc) {
	case "strict":
		return severityMedium, severityLow
	case "permissive":
		return severityCritical, severityHigh
	default:
		return severityCritical, severityMedium
	}
}

func guardrailProfile(gc *config.GuardrailConfig) string {
	if gc == nil {
		return "default"
	}
	dir := strings.ToLower(strings.TrimSpace(gc.RulePackDir))
	if dir == "" {
		return "default"
	}
	base := strings.ToLower(filepath.Base(filepath.Clean(dir)))
	switch base {
	case "strict", "permissive", "default", "balanced":
		if base == "balanced" {
			return "default"
		}
		return base
	default:
		return "default"
	}
}

func hiltEnabled(gc *config.GuardrailConfig) bool {
	return gc != nil && gc.HILT.Enabled
}

func hiltMinRank(gc *config.GuardrailConfig) int {
	if gc == nil {
		return severityHigh
	}
	rank := guardrailSeverityRank(gc.HILT.MinSeverity)
	if rank <= severityNone {
		return severityHigh
	}
	return rank
}

func guardrailSeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return severityCritical
	case "HIGH":
		return severityHigh
	case "MEDIUM":
		return severityMedium
	case "LOW":
		return severityLow
	default:
		return severityNone
	}
}

func normalizedGuardrailAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny":
		return guardrailActionBlock
	case "confirm", "ask":
		return guardrailActionConfirm
	case "alert", "warn", "warning":
		return guardrailActionAlert
	default:
		return guardrailActionAllow
	}
}
