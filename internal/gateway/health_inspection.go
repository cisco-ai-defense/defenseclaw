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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// standaloneInspectionPosture is the "inspection" object a standalone
// gateway publishes on /health; the Linux and macOS lifecycle copies it into
// the status, ensure and verify results. The values follow the lifecycle
// result contract (packaging/mdm/contract/lifecycle-result.schema.json):
//
//   - local: "active" while the local policy engine answers hooks (the
//     guardrail is running, or starting while the guardian's authorization
//     is verified), "disabled" when the guardrail is turned off or stopped,
//     "unknown" otherwise;
//   - ai_defense: "disabled" unless enterprise.inspection.ai_defense is
//     enabled, then "ok", or "unavailable:<code>" with the reason the
//     guardrail detail reports, or "unknown" before the guardrail has
//     published its AI Defense state.
func standaloneInspectionPosture(cfg *config.Config, guardrail SubsystemHealth) map[string]string {
	local := "unknown"
	switch guardrail.State {
	case StateRunning, StateStarting:
		local = "active"
	case StateDisabled, StateStopped:
		local = "disabled"
	}
	aiDefense := "disabled"
	if cfg != nil && cfg.Enterprise.Inspection.AIDefense.Enabled {
		aiDefense = "unknown"
		if available, ok := guardrail.Details["ai_defense_available"].(bool); ok {
			if available {
				aiDefense = "ok"
			} else {
				reason, _ := guardrail.Details["ai_defense_error"].(string)
				aiDefense = "unavailable:" + aiDefenseUnavailableCode(reason)
			}
		}
	}
	return map[string]string{"local": local, "ai_defense": aiDefense}
}

// aiDefenseUnavailableCode maps the AI Defense error the guardrail detail
// carries ("ai_defense: <reason>") to a stable code.
func aiDefenseUnavailableCode(reason string) string {
	reason = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reason), "ai_defense:"))
	switch {
	case reason == "" || strings.Contains(reason, "client not initialized"):
		return "not_initialized"
	case strings.Contains(reason, "API key was rejected"):
		return "auth_failed"
	case strings.Contains(reason, "proxy requires authentication"):
		return "proxy_auth_required"
	case strings.HasPrefix(reason, "credential "):
		return "credential_unavailable"
	case strings.HasPrefix(reason, "enterprise.network"):
		return "proxy_config"
	case strings.Contains(reason, "unreachable"):
		return "unreachable"
	default:
		return "error"
	}
}
