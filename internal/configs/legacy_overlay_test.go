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

package configs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// GAP-0184: the legacy rule is ApplyOverlay with the extra_headers of
// releases before 1.0.3: a same-name merge keeps the earlier entry's headers
// and drops the later entry's; every other field merges as ApplyOverlay
// merges it.
func TestApplyLegacyOverlayKeepsTheEarlierHeaders(t *testing.T) {
	entries := func() []Provider {
		return []Provider{
			{Name: "acme", Domains: []string{"a.example"}, BaseURL: "https://a.example/v1",
				ExtraHeaders: map[string]string{"x-team": "first"}},
			{Name: "ACME", Domains: []string{"b.example"}, BaseURL: "https://b.example/v1",
				RequestPathOverrides: map[string]string{"chat": "/b/chat"},
				ExtraHeaders:         map[string]string{"x-team": "second", "x-route": "eu"}},
			{Name: "openai", ExtraHeaders: map[string]string{"x-openai": "dropped"}},
		}
	}
	builtin := func() *ProvidersConfig {
		return &ProvidersConfig{Providers: []Provider{{Name: "openai", Domains: []string{"api.openai.com"}}}}
	}
	legacy, current := builtin(), builtin()
	ApplyLegacyOverlay(legacy, ProvidersConfig{Providers: entries()})
	ApplyOverlay(current, ProvidersConfig{Providers: entries()})
	if len(legacy.Providers) != 2 || len(current.Providers) != 2 {
		t.Fatalf("providers: legacy %d, current %d, want 2", len(legacy.Providers), len(current.Providers))
	}
	if got := legacy.Providers[1].ExtraHeaders; !reflect.DeepEqual(got, map[string]string{"x-team": "first"}) {
		t.Errorf("legacy acme headers = %v, want the first entry's", got)
	}
	if got := legacy.Providers[0].ExtraHeaders; got != nil {
		t.Errorf("legacy openai headers = %v, want none (the built-in had none)", got)
	}
	if got := current.Providers[1].ExtraHeaders; !reflect.DeepEqual(got, map[string]string{"x-team": "second", "x-route": "eu"}) {
		t.Errorf("current acme headers = %v", got)
	}
	// Apart from the headers, both rules give the same registry.
	for i := range legacy.Providers {
		l, c := legacy.Providers[i], current.Providers[i]
		l.ExtraHeaders, c.ExtraHeaders = nil, nil
		if !reflect.DeepEqual(l, c) {
			t.Errorf("provider %d: legacy %+v, current %+v", i, l, c)
		}
	}
}

// GAP-0184: LoadProvidersWithOverlay reports a legacy overlay it merged, and
// only that: an absent file or a derived one (rendered from config.yaml) is
// no input.
func TestLoadProvidersWithOverlayReportsALegacyOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)
	for _, tc := range []struct {
		name, overlay string
		legacy        bool
	}{
		{name: "absent"},
		{name: "derived", overlay: `{"_derived_from":"sha256:00","providers":[{"name":"acme","domains":["a.example"]}]}`},
		{name: "legacy", overlay: `{"providers":[{"name":"acme","domains":["a.example"]}]}`, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(path)
			if tc.overlay != "" {
				if err := os.WriteFile(path, []byte(tc.overlay), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, legacy, err := LoadProvidersWithOverlay()
			if err != nil {
				t.Fatal(err)
			}
			if legacy != tc.legacy {
				t.Errorf("legacy overlay = %v, want %v", legacy, tc.legacy)
			}
			if len(cfg.Providers) == 0 {
				t.Error("no built-in providers")
			}
		})
	}
}
