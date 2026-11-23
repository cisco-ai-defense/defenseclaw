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
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// GAP-1813: the publisher a SKILL.md declares is free text, so it is content
// class and every redacting profile scans it, like the declared description.
func TestGAP1813DeclaredPublisherIsRedacted(t *testing.T) {
	// AWS's documented example key, built at run time so the source holds no key-shaped literal.
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	signal := skillReportSignal("claudecode", "claudecode", "sha256:"+strings.Repeat("1", 64),
		inventory.AIEvidence{Type: "skill_entry", Basename: "deploy", Skill: &inventory.AISkillFacts{
			ContentStatus: inventory.SkillContentTooLarge, Scope: inventory.SkillScopeUser,
			Author: "key " + secret + " team",
		}},
	)
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []observability.ProducerKey{
		config.ObservabilityV8ManagedSkillInventoryAction, observability.ProducerKey("skill_inventory"),
	} {
		capture := &endpointInventoryCapture{}
		if err := emitEndpointInventorySnapshot(
			t.Context(), capture, endpointSkillInventorySource,
			discoveredEntriesFromReport(inventory.AIDiscoveryReport{Signals: []inventory.AISignal{signal}}, inventory.SignalSkill, "skill"),
			false, action, endpointInventoryCycle{},
		); err != nil {
			t.Fatal(err)
		}
		for _, name := range []redaction.ProfileName{redaction.ProfileSensitive, redaction.ProfileContent} {
			profile, ok := redaction.BuiltInProfile(name)
			if !ok {
				t.Fatalf("no %s profile", name)
			}
			checked := 0
			for _, record := range capture.snapshot() {
				if record.EventName() != "ai_component.observed" {
					continue
				}
				body, _ := record.Body()
				object, err := body.Object()
				if err != nil {
					t.Fatal(err)
				}
				if object[observability.TelemetryAttributeDefenseClawInventorySkillPublisher] == nil {
					t.Fatalf("%s: the declared publisher is not on the record", action)
				}
				projection, _, err := engine.Project(record, profile)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := projection.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(payload), secret) {
					t.Fatalf("%s under %s leaks the key in the publisher: %s", action, name, payload)
				}
				checked++
			}
			if checked != 1 {
				t.Fatalf("%s under %s: checked %d records, want 1", action, name, checked)
			}
		}
	}
}
