// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package config

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

// schemaObjectProperties follows path (property names, with $ref resolved at
// every step) from the v8 config schema root and returns that object's
// declared property names. It fails the test unless the object is closed.
func schemaObjectProperties(t *testing.T, path ...string) []string {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	defs, _ := schema["$defs"].(map[string]any)
	resolve := func(node map[string]any) map[string]any {
		for {
			ref, ok := node["$ref"].(string)
			if !ok {
				return node
			}
			next, ok := defs[ref[strings.LastIndex(ref, "/")+1:]].(map[string]any)
			if !ok {
				t.Fatalf("unresolvable $ref %q", ref)
			}
			node = next
		}
	}
	node := resolve(schema)
	for _, name := range path {
		properties, _ := node["properties"].(map[string]any)
		child, ok := properties[name].(map[string]any)
		if !ok {
			t.Fatalf("schema has no property %q along %v", name, path)
		}
		node = resolve(child)
	}
	if open, isBool := node["additionalProperties"].(bool); !isBool || open {
		t.Fatalf("schema object %v is not closed", path)
	}
	properties, _ := node["properties"].(map[string]any)
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// yamlFieldNames returns the yaml keys of a struct type, sorted.
func yamlFieldNames(typ reflect.Type) []string {
	names := []string{}
	for index := 0; index < typ.NumField(); index++ {
		name := strings.Split(typ.Field(index).Tag.Get("yaml"), ",")[0]
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// TestAIRuntimeConfigMatchesTheClosedSchema pins the runtime block's Go keys to
// the v8 schema. A Go-only key (the retired acquisition and helper_socket) is
// a setting no config.yaml can carry, because the closed schema rejects it.
func TestAIRuntimeConfigMatchesTheClosedSchema(t *testing.T) {
	got := yamlFieldNames(reflect.TypeOf(AIRuntimeConfig{}))
	want := schemaObjectProperties(t, "ai_discovery", "runtime")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AIRuntimeConfig yaml keys = %v, schema ai_discovery.runtime = %v", got, want)
	}
}

func TestAIRuntimeDefaultsAreAppliedNotZero(t *testing.T) {
	t.Parallel()
	var runtime AIRuntimeConfig
	if got := runtime.EffectivePollInterval(); got != DefaultRuntimePollIntervalSec*time.Second {
		t.Errorf("EffectivePollInterval() = %s", got)
	}
	if got := runtime.EffectiveMinRisk(); got != DefaultRuntimeMinRiskToReport {
		t.Errorf("EffectiveMinRisk() = %d", got)
	}
	if got := runtime.EffectiveChainWindow(); got != DefaultRuntimeChainWindowMin*time.Minute {
		t.Errorf("EffectiveChainWindow() = %s", got)
	}
	if !runtime.CorrelationEnabled() {
		t.Error("correlation defaults off; it should default on")
	}
}

// TestCorrelationOptOutIsExplicit pins the difference between "do not consult
// the inventory" and "the inventory disagreed". Only the operator's explicit
// false removes the read.
func TestCorrelationOptOutIsExplicit(t *testing.T) {
	t.Parallel()
	off := false
	on := true
	if (AIRuntimeConfig{Correlate: &off}).CorrelationEnabled() {
		t.Error("explicit false did not disable correlation")
	}
	if !(AIRuntimeConfig{Correlate: &on}).CorrelationEnabled() {
		t.Error("explicit true did not enable correlation")
	}
}

// TestPlaneCIsNeverImplied pins that the kernel-event plane must be asked for
// explicitly, because the host-plane opt-in is where the privilege and privacy
// decision is recorded.
func TestPlaneCIsNeverImplied(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input AIRuntimeConfig
		want  []string
	}{
		{"empty selection", AIRuntimeConfig{}, []string{"a", "b"}},
		{"empty selection with host plane", AIRuntimeConfig{EnableHostPlane: true}, []string{"a", "b", "c"}},
		{
			"c requested without the opt-in",
			AIRuntimeConfig{Planes: []string{"a", "c"}},
			[]string{"a"},
		},
		{
			"c requested with the opt-in",
			AIRuntimeConfig{Planes: []string{"c", "a"}, EnableHostPlane: true},
			[]string{"a", "c"},
		},
		{
			"case and whitespace tolerated, order normalised",
			AIRuntimeConfig{Planes: []string{" B ", "A"}},
			[]string{"a", "b"},
		},
		{
			"an unknown plane is ignored rather than guessed at",
			AIRuntimeConfig{Planes: []string{"a", "z"}},
			[]string{"a"},
		},
		{
			// Nothing recognised is not the same as nothing configured. A
			// typo must not silently fall back to the default selection and
			// start running planes the operator did not ask for.
			"every named plane unknown selects none",
			AIRuntimeConfig{Planes: []string{"z", "q"}},
			[]string{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.input.EffectivePlanes(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("EffectivePlanes() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestRuntimeIsDisabledOnAZeroValueConfig pins that an existing config which
// has never heard of the runtime planes does not gain them on upgrade.
func TestRuntimeIsDisabledOnAZeroValueConfig(t *testing.T) {
	t.Parallel()
	var discovery AIDiscoveryConfig
	if discovery.Runtime.Enabled {
		t.Fatal("the runtime planes are enabled on a zero-value AIDiscoveryConfig")
	}
	if discovery.Runtime.EnableHostPlane {
		t.Fatal("the host plane is enabled on a zero-value AIDiscoveryConfig")
	}
}
