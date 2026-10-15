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

package enterprisebundle_test

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

func TestBundleCapabilityLoss(t *testing.T) {
	current := []byte(`config_version: 9
enterprise:
  openshell: {driver: vm}
  machine_policy:
    connectors: {hermes: {managed_hooks_only: enforce}}
openshell: {enabled: true}
guardrail:
  enabled: true
  connectors: {hermes: {enabled: true}}
asset_policy: {enabled: true}
observability:
  destinations: [{name: security, kind: otlp, endpoint: https://example.invalid}]
`)
	next := []byte("config_version: 9\n")
	loss, err := enterprisebundle.DisabledByBundle(current, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sandbox", "enterprise.openshell", "guardrail", "guardrail.hermes", "asset_policy", "observability.security"} {
		if !slices.Contains(loss, id) {
			t.Errorf("disabled_by_bundle = %v, missing %s", loss, id)
		}
	}
	if loss, err := enterprisebundle.DisabledByBundle(next, current); err != nil || len(loss) != 0 {
		t.Fatalf("enabling capabilities = %v, %v", loss, err)
	}
}

func TestBundleMachinePolicyBuiltInDefault(t *testing.T) {
	current := []byte("enterprise:\n  machine_policy:\n    connectors: {hermes: {ownership: merge}}\n")
	for _, tc := range []struct {
		name, next string
		want       bool
	}{
		{"section omitted retains built-in hooks", "enterprise: {profile: standalone}\n", false},
		{"ownership off disables hooks", "enterprise:\n  machine_policy:\n    default: {ownership: off}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loss, err := enterprisebundle.DisabledByBundle(current, []byte(tc.next))
			if err != nil || slices.Contains(loss, "machine_policy.hermes") != tc.want {
				t.Fatalf("loss = %v, err = %v", loss, err)
			}
		})
	}
}

func TestBundleGuardrailConnectorInheritance(t *testing.T) {
	current := []byte("guardrail:\n  enabled: true\n  connectors: {hermes: {enabled: true}}\n")
	for _, tc := range []struct {
		name, next string
		loss       bool
	}{
		{"inherits", "guardrail: {enabled: true}\n", false},
		{"disabled", "guardrail:\n  enabled: true\n  connectors: {hermes: {enabled: false}}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loss, err := enterprisebundle.DisabledByBundle(current, []byte(tc.next))
			if err != nil || slices.Contains(loss, "guardrail.hermes") != tc.loss {
				t.Fatalf("loss = %v, err = %v", loss, err)
			}
		})
	}
}

func TestBundleGuardrailSelectedConnectorLoss(t *testing.T) {
	current := []byte("guardrail: {enabled: true, connector: hermes}\n")
	next := []byte("guardrail: {enabled: true, connector: codex}\n")
	loss, err := enterprisebundle.DisabledByBundle(current, next)
	if err != nil || !slices.Contains(loss, "guardrail.connector.hermes") {
		t.Fatalf("loss = %v, err = %v", loss, err)
	}
}
