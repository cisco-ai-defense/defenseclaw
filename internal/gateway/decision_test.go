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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGuardrailRuntimeActionBalanced(t *testing.T) {
	cfg := &config.Config{}
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "alert" {
		t.Fatalf("HIGH balanced action = %q, want alert", got)
	}
	if got := guardrailRuntimeAction(cfg, "CRITICAL", true); got != "block" {
		t.Fatalf("CRITICAL balanced action = %q, want block", got)
	}
}

func TestGuardrailRuntimeActionHILT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "confirm" {
		t.Fatalf("HIGH HILT confirmable action = %q, want confirm", got)
	}
	if got := guardrailRuntimeAction(cfg, "HIGH", false); got != "alert" {
		t.Fatalf("HIGH HILT unsupported action = %q, want alert", got)
	}
	if got := guardrailRuntimeAction(cfg, "CRITICAL", true); got != "block" {
		t.Fatalf("CRITICAL HILT action = %q, want block", got)
	}
}

func TestGuardrailRuntimeActionStrictBlocksBeforeHILT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/tmp/policies/guardrail/strict"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	if got := guardrailRuntimeAction(cfg, "MEDIUM", true); got != "block" {
		t.Fatalf("MEDIUM strict action = %q, want block", got)
	}
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "block" {
		t.Fatalf("HIGH strict action = %q, want block", got)
	}
}
