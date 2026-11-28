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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// skillInventoryActionName is config.ObservabilityV8SkillInventoryAction,
// spelled out so the fail-before run compiles against the parent.
const skillInventoryActionName observability.ProducerKey = "skill_inventory"

var skillProductsManifest = []byte("---\nname: pdf\ndescription: Fill PDF forms\n---\nUse the form tool.\n")

func skillProductsManifestHash() string {
	sum := sha256.Sum256(skillProductsManifest)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func skillProductsReport(scanID string, skills ...inventory.AIEvidence) *inventory.AIDiscoveryReport {
	return &inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{ScanID: scanID, Source: "scheduled", PrivacyMode: "enhanced", Result: "ok"},
		Signals: []inventory.AISignal{skillReportSignal("codex", "codex", "sha256:"+strings.Repeat("1", 64), skills...)},
	}
}

func skillProductsPDF() inventory.AIEvidence {
	return inventory.AIEvidence{Type: "skill_entry", Basename: "pdf", Skill: &inventory.AISkillFacts{
		ContentHash: "sha256:" + strings.Repeat("c", 64), ContentStatus: inventory.SkillContentOK,
		Scope: inventory.SkillScopeUser, Location: "~/.agents/skills/pdf", Description: "Fill PDF forms",
		ManifestHash: skillProductsManifestHash(), ManifestSize: int64(len(skillProductsManifest)),
	}}
}

// skillProductsBodies returns the skill records of capture, each checked to
// carry want as its routing action.
func skillProductsBodies(t *testing.T, capture *endpointInventoryCapture, want observability.ProducerKey) []map[string]any {
	t.Helper()
	var bodies []map[string]any
	for _, record := range capture.snapshot() {
		if canonicalBody(t, record)[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != endpointSkillInventorySource {
			continue
		}
		if record.Action() != string(want) {
			t.Fatalf("record %s has action %q, want %q", record.EventName(), record.Action(), want)
		}
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, _ := record.Body()
		object, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, object)
	}
	return bodies
}

// The skill inventory runs in every product with ai_discovery on. Outside
// Secure Client it goes to the operator's own destinations under its own
// action, with new/changed/removed state kept in the gateway's data dir, and
// without SKILL.md text unless ai_discovery.include_skill_manifests is on.
func TestSkillInventoryIsSentOutsideSecureClient(t *testing.T) {
	for _, product := range []struct{ name, mode, profile string }{
		{name: "oss per-user"},
		{name: "managed standalone", mode: "managed_enterprise", profile: "standalone"},
	} {
		t.Run(product.name, func(t *testing.T) {
			withManagedEnterprise(t, false)
			dataDir := t.TempDir()
			cfg := &config.Config{
				DataDir: dataDir, DeploymentMode: product.mode,
				AIDiscovery: config.AIDiscoveryConfig{Enabled: true},
			}
			cfg.Enterprise.Profile = product.profile
			gate := newManagedInventoryPublishState(cfg)
			gate.SetSkillManifestReader(func(string) ([]byte, bool) { return skillProductsManifest, true })
			emit := func(report *inventory.AIDiscoveryReport) []map[string]any {
				t.Helper()
				capture := &endpointInventoryCapture{}
				if err := emitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture, false, report, gate); err != nil {
					t.Fatal(err)
				}
				return skillProductsBodies(t, capture, skillInventoryActionName)
			}

			bodies := emit(skillProductsReport("scan-1", skillProductsPDF()))
			if len(bodies) != 1 {
				t.Fatalf("got %d skill records, want 1", len(bodies))
			}
			body := bodies[0]
			for key, want := range map[string]any{
				observability.TelemetryAttributeDefenseClawInventorySkillState:       "new",
				observability.TelemetryAttributeDefenseClawInventorySkillContentHash: "sha256:" + strings.Repeat("c", 64),
				observability.TelemetryAttributeDefenseClawInventorySkillLocation:    "~/.agents/skills/pdf",
				observability.TelemetryAttributeDefenseClawInventoryItemDescription:  "Fill PDF forms",
			} {
				if body[key] != want {
					t.Errorf("%s = %v, want %v", key, body[key], want)
				}
			}
			if _, ok := body[observability.TelemetryAttributeDefenseClawInventorySkillManifest]; ok {
				t.Fatal("SKILL.md text was sent with include_skill_manifests off")
			}
			if _, err := os.Stat(filepath.Join(dataDir, "endpoint_inventory_publish_state.json")); err != nil {
				t.Fatalf("the skill state was not kept: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dataDir, managedInventoryPublishStateFile)); !os.IsNotExist(err) {
				t.Fatalf("the Secure Client state file was written: %v", err)
			}

			if bodies := emit(skillProductsReport("scan-2", skillProductsPDF())); len(bodies) != 0 {
				t.Fatalf("an unchanged skill collection was sent again: %d records", len(bodies))
			}
			bodies = emit(skillProductsReport("scan-3"))
			if len(bodies) != 1 || bodies[0][observability.TelemetryAttributeDefenseClawInventorySkillState] != "removed" {
				t.Fatalf("removal: %v", bodies)
			}

			// The text is added only with the key on.
			cfg.AIDiscovery.IncludeSkillManifests = true
			bodies = emit(skillProductsReport("scan-4", skillProductsPDF()))
			if len(bodies) != 1 || bodies[0][observability.TelemetryAttributeDefenseClawInventorySkillManifest] != string(skillProductsManifest) {
				t.Fatalf("include_skill_manifests on: %v", bodies)
			}
		})
	}
}

// skillProductsNamed returns n skill folders named prefix-000 and up.
func skillProductsNamed(prefix string, n int) []inventory.AIEvidence {
	skills := make([]inventory.AIEvidence, n)
	for i := range skills {
		name := fmt.Sprintf("%s-%03d", prefix, i)
		sum := sha256.Sum256([]byte(name))
		skills[i] = inventory.AIEvidence{Type: "skill_entry", Basename: name, Skill: &inventory.AISkillFacts{
			ContentHash: "sha256:" + hex.EncodeToString(sum[:]), ContentStatus: inventory.SkillContentOK,
			Scope: inventory.SkillScopeUser, Location: "~/.agents/skills/" + name,
		}}
	}
	return skills
}

// Outside Secure Client a skill turnover larger than the collection limit
// also sends its removals first, in bounded batches under the operator
// action, so the current collection still goes out whole and the next scan
// finds nothing left to send.
func TestSkillTurnoverOutsideSecureClientSendsRemovalsFirst(t *testing.T) {
	for _, product := range []struct{ name, mode, profile string }{
		{name: "oss per-user"},
		{name: "managed standalone", mode: "managed_enterprise", profile: "standalone"},
	} {
		t.Run(product.name, func(t *testing.T) {
			withManagedEnterprise(t, false)
			testenv.SetHome(t, t.TempDir())
			cfg := &config.Config{
				DataDir: t.TempDir(), DeploymentMode: product.mode,
				AIDiscovery: config.AIDiscoveryConfig{Enabled: true},
			}
			cfg.Enterprise.Profile = product.profile
			gate := newManagedInventoryPublishState(cfg)
			emit := func(report *inventory.AIDiscoveryReport) map[any]int {
				t.Helper()
				capture := &endpointInventoryCapture{}
				if err := emitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture, false, report, gate); err != nil {
					t.Fatal(err)
				}
				states := map[any]int{}
				for _, body := range skillProductsBodies(t, capture, skillInventoryActionName) {
					states[body[observability.TelemetryAttributeDefenseClawInventorySkillState]]++
				}
				return states
			}
			if got := emit(skillProductsReport("scan-1", skillProductsNamed("old", 300)...)); got["new"] != 300 || len(got) != 1 {
				t.Fatalf("first scan: %v", got)
			}
			// 300 removed plus 300 new is over the limit of 512 for one collection.
			if got := emit(skillProductsReport("scan-2", skillProductsNamed("next", 300)...)); got["removed"] != 300 || got["new"] != 300 || len(got) != 2 {
				t.Fatalf("turnover: %v, want 300 removed and 300 new", got)
			}
			if got := emit(skillProductsReport("scan-3", skillProductsNamed("next", 300)...)); len(got) != 0 {
				t.Fatalf("an unchanged collection was sent again after the turnover: %v", got)
			}
		})
	}
}

// Every endpoint collection, not only skills, is sent outside Secure Client
// under its operator action; none uses a managed action, and an unchanged
// second scan sends nothing. The actions are spelled out so the fail-before
// run compiles against the parent.
func TestEndpointInventoryIsSentOutsideSecureClient(t *testing.T) {
	want := map[string]observability.ProducerKey{
		endpointConnectorInventorySource:       "connector_inventory",
		endpointMCPInventorySource:             "mcp_inventory",
		"endpoint_discovered_mcp_inventory":    "mcp_inventory",
		"endpoint_per_connector_mcp_inventory": "mcp_inventory",
		endpointSkillInventorySource:           skillInventoryActionName,
		"endpoint_plugin_inventory":            "plugin_inventory",
	}
	for _, product := range []struct{ name, mode, profile string }{
		{name: "oss per-user"},
		{name: "managed standalone", mode: "managed_enterprise", profile: "standalone"},
	} {
		t.Run(product.name, func(t *testing.T) {
			withManagedEnterprise(t, false)
			testenv.SetHome(t, t.TempDir())
			cfg := &config.Config{
				DataDir: t.TempDir(), DeploymentMode: product.mode,
				AIDiscovery: config.AIDiscoveryConfig{Enabled: true},
			}
			cfg.Enterprise.Profile = product.profile
			gate := newManagedInventoryPublishState(cfg)
			emit := func(scanID string) []observability.Record {
				t.Helper()
				capture := &endpointInventoryCapture{}
				err := emitEndpointInventory(t.Context(), cfg, connector.NewDefaultRegistry(), capture, false,
					skillProductsReport(scanID, skillProductsPDF()), gate)
				if err != nil {
					t.Fatal(err)
				}
				return capture.snapshot()
			}
			seen := map[string]bool{}
			for _, record := range emit("scan-1") {
				source, _ := canonicalBody(t, record)[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
				if strings.HasPrefix(record.Action(), "managed_") {
					t.Fatalf("%s used the managed action %q", source, record.Action())
				}
				if action, ok := want[source]; ok {
					if record.Action() != string(action) {
						t.Fatalf("%s action = %q, want %q", source, record.Action(), action)
					}
					seen[source] = true
				}
			}
			for source := range want {
				if !seen[source] {
					t.Errorf("collection %s was not sent", source)
				}
			}
			if records := emit("scan-2"); len(records) != 0 {
				t.Fatalf("an unchanged scan sent %d records", len(records))
			}
		})
	}
}
