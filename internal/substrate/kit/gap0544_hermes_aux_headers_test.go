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

//go:build linux

package kit

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// GAP-0544: Hermes builds its auxiliary clients (title generation,
// compression, vision) with model.default_headers / model.extra_headers only,
// not with the provider's extra_headers. The managed config put the actor
// placeholder on the provider alone, so the title call after a streamed
// answer carried none and /llm answered 401 missing_token. The model block
// now carries the same headers as the provider.
func TestGAP0544HermesAuxiliaryCallsCarryThePlaceholder(t *testing.T) {
	ov := wave2Overlay(t, "hermes")
	var doc struct {
		Model struct {
			Provider     string            `yaml:"provider"`
			ExtraHeaders map[string]string `yaml:"extra_headers"`
		} `yaml:"model"`
		Providers map[string]struct {
			ExtraHeaders map[string]string `yaml:"extra_headers"`
		} `yaml:"providers"`
	}
	if err := yaml.Unmarshal(file(ov, "/etc/hermes/config.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Model.Provider != "defenseclaw" {
		t.Fatalf("model provider %q", doc.Model.Provider)
	}
	main := doc.Providers["defenseclaw"].ExtraHeaders
	if main[PlaceholderHeader] != PlaceholderValue {
		t.Fatalf("the defenseclaw provider lost its placeholder: %v", main)
	}
	if got := doc.Model.ExtraHeaders[PlaceholderHeader]; got != PlaceholderValue {
		t.Fatalf("model.extra_headers %v: auxiliary calls (title generation) carry no %s", doc.Model.ExtraHeaders, PlaceholderHeader)
	}
	for k, v := range main {
		if doc.Model.ExtraHeaders[k] != v {
			t.Errorf("model.extra_headers[%s] = %q, provider has %q", k, doc.Model.ExtraHeaders[k], v)
		}
	}
}
