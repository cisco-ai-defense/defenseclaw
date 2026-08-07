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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

const builtInMatchReasonPrefix = "matched: "

// trustedBuiltInMatchReason reports whether reason consists exclusively of
// exact rule ID/title pairs from the compiled-in catalog. The equality check
// is deliberately stricter than a character allow-list: scanner-provided
// titles can contain matched literals that merely look like harmless metadata.
func trustedBuiltInMatchReason(reason string) bool {
	body, ok := strings.CutPrefix(reason, builtInMatchReasonPrefix)
	if !ok || body == "" {
		return false
	}
	labels := strings.Split(body, ", ")
	if len(labels) == 0 || len(labels) > 5 {
		return false
	}
	for _, label := range labels {
		if !trustedBuiltInFindingLabel(label) {
			return false
		}
	}
	return true
}

func trustedBuiltInFindingLabel(label string) bool {
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			base := rule.ID + ":" + rule.Title
			if label == base || label == base+" (obfuscated)" {
				return true
			}
		}
	}
	return false
}

// agentDisplayReason keeps exact, ship-authored catalog metadata readable on
// agent surfaces while retaining the existing scrub for every free-form or
// scanner-authored reason.
func agentDisplayReason(reason string) string {
	if trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ReasonForAgent(reason)
}

// notificationDisplayReason applies the same narrow catalog carve-out to OS
// notifications only under the default compatibility policy. An explicit
// managed-enterprise redact directive remains authoritative.
func notificationDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy == redaction.SinkPolicyDefault && trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ReasonForSink(reason, policy)
}

// defaultSinkDisplayReason is used by compatibility response bodies that do
// not carry a request-scoped managed policy.
func defaultSinkDisplayReason(reason string) string {
	if trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ForSinkReason(reason)
}
