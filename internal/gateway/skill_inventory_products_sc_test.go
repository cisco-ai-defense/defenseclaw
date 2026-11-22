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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Secure Client keeps its own action and state file; the skill_inventory
// action is never used there.
func TestSkillInventoryOnSecureClientKeepsTheManagedAction(t *testing.T) {
	withManagedEnterprise(t, true)
	dataDir := t.TempDir()
	cfg := &config.Config{
		DataDir: dataDir, DeploymentMode: "managed_enterprise",
		AIDiscovery: config.AIDiscoveryConfig{Enabled: true},
	}
	gate := newManagedInventoryPublishState(cfg)
	if gate == nil || filepath.Base(gate.path) != managedInventoryPublishStateFile {
		t.Fatalf("Secure Client publish state: %+v", gate)
	}
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture, false, skillProductsReport("scan-1", skillProductsPDF()), gate); err != nil {
		t.Fatal(err)
	}
	skills := 0
	for _, record := range capture.snapshot() {
		if _, operator := operatorInventoryActions[observability.ProducerKey(record.Action())]; operator {
			t.Fatalf("a Secure Client endpoint used the operator action %q", record.Action())
		}
		if record.Action() == string(config.ObservabilityV8ManagedSkillInventoryAction) && record.EventName() == "ai_component.observed" {
			skills++
		}
	}
	if skills != 1 {
		t.Fatalf("managed skill records = %d, want 1", skills)
	}
}

// With ai_discovery off nothing is sent, whatever the product.
func TestSkillInventoryNeedsAIDiscovery(t *testing.T) {
	withManagedEnterprise(t, false)
	cfg := &config.Config{DataDir: t.TempDir()}
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture, false,
		skillProductsReport("scan-1", skillProductsPDF()), newManagedInventoryPublishState(cfg)); err != nil {
		t.Fatal(err)
	}
	if n := len(capture.snapshot()); n != 0 {
		t.Fatalf("ai_discovery off sent %d records", n)
	}
}

func TestSkillInventoryActionNameMatchesConfig(t *testing.T) {
	if skillInventoryActionName != config.ObservabilityV8SkillInventoryAction {
		t.Fatalf("test action %q, config action %q", skillInventoryActionName, config.ObservabilityV8SkillInventoryAction)
	}
}
