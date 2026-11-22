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
	"context"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0155: serve --substrate runs no host connector guardrail. A managed
// config whose host guardrail boot fails (here the scoped hook token cannot
// be written) is idle under the Substrate builder: no error, no error health.
func TestSubstrateGatewayRunsNoHostConnectorGuardrail(t *testing.T) {
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Gateway:        config.GatewayConfig{Token: "gateway-token"},
			Guardrail: config.GuardrailConfig{
				Enabled:   true,
				Connector: "codex",
				Mode:      "action",
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}
	s.SetSubstrate(func(*APIServer, http.Handler) (SubstrateConfig, error) {
		return SubstrateConfig{}, nil
	})

	if err := s.runActiveGuardrail(context.Background()); err != nil {
		t.Fatalf("runActiveGuardrail under serve --substrate = %v, want no host guardrail boot", err)
	}
	if snapshot := s.health.Snapshot(); snapshot.Guardrail.State == StateError {
		t.Fatalf("guardrail health = %s (%q), want no host guardrail error", snapshot.Guardrail.State, snapshot.Guardrail.LastError)
	}
}
