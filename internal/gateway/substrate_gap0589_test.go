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
	"reflect"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// substrate-1:GAP-0589. Once a ConfigMap edit reloads a Substrate gateway
// (GAP-0579), an llm_providers edit applied live in the gateway while the
// controller kept the provider egress hosts it started with, and the
// Substrate follower and reference page said llm_providers applies at the
// pod's restart. A Substrate gateway now keeps the running llm_providers
// and applies the rest of the edit; a host gateway still takes it live.
func TestGAP0589SubstrateGatewayHoldsLLMProvidersUntilRestart(t *testing.T) {
	edit := func(boot *config.Config) *config.Config {
		next := cloneConfig(boot)
		next.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "acme", Domains: []string{"llm.acme.example"}}}
		next.Guardrail.BlockAt = "HIGH"
		return next
	}

	boot := config.DefaultConfig()
	boot.Substrate.Enabled = true
	next := edit(boot)
	diff := diffConfigs(boot, next)
	if !slices.Contains(diff.RestartRequired, "llm_providers") {
		t.Fatalf("Substrate: llm_providers is applied live (restart_required=%v), the controller keeps its boot provider hosts", diff.RestartRequired)
	}
	held := holdRestartRequired(boot, next, diff.RestartRequired)
	if held == nil {
		t.Fatalf("Substrate: llm_providers cannot be held, so the whole reload would fail: %v", diff.RestartRequired)
	}
	heldDiff := diffConfigs(boot, held)
	if len(heldDiff.RestartRequired) != 0 || !reflect.DeepEqual(held.LLMProviders, boot.LLMProviders) ||
		held.Guardrail.BlockAt != "HIGH" {
		t.Fatalf("Substrate held: restart=%v providers=%+v block_at=%q, want the boot providers and the rest applied",
			heldDiff.RestartRequired, held.LLMProviders, held.Guardrail.BlockAt)
	}

	host := config.DefaultConfig()
	hostDiff := diffConfigs(host, edit(host))
	if slices.Contains(hostDiff.RestartRequired, "llm_providers") || !slices.Contains(hostDiff.Changed, "llm_providers") {
		t.Fatalf("host gateway: changed=%v restart=%v, want llm_providers hot", hostDiff.Changed, hostDiff.RestartRequired)
	}
}
