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
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// providersFoldOverlayResolved is the fixture's legacy overlay once the
// operator kept config.yaml's values: the four conflicting fields
// (profile_id, base_url, request_path_overrides.chat,
// extra_headers.X-B11-Config) are gone.
const providersFoldOverlayResolved = `{"providers":[{"name":"acme-gw","domains":["b11-acme-alt.example.test"],
  "env_keys":["B11_ACME_LEGACY_DUMMY_KEY"],"request_path_overrides":{"legacy":"/legacy/only"},
  "extra_headers":{"X-B11-Legacy":"dummy-legacy"}}],"ollama_ports":[]}`

// GAP-0184: an upgrade whose fold of a conflicting legacy
// custom-providers.json is refused changes nothing live. For a home that
// 1.0.1 or 1.0.2 wrote (internal/config/testdata/providers-fold: config.yaml
// plus the operator's overlay), the registry the gateway builds equals,
// field by field and extra_headers included, the one the published 1.0.2
// gateway served for the same files, before and after the migration.
// testdata/providers_fold/registry-1.0.2.json is that capture: GET
// /v1/config/providers in lane G-B-11-A2U-04 (TST-1313), its openai and
// acme-gw entries. 1.0.1 builds the registry with the same code (the
// configs.ApplyOverlay merge and the generation order are unchanged between
// the 1.0.1 and 1.0.2 tags), so the capture is its baseline too. 1.0.2 sent
// the overlay's acme-gw X-B11-Config and none of config.yaml's openai
// headers; the build before this fix sent config.yaml's.
//
// Once the operator resolves the conflict and the fold runs, the file is no
// longer an input and the GAP-0361 rule applies: config.yaml's headers of
// the same-name entries are sent too, exactly the ones the fold names.
func TestRefusedProvidersFoldKeepsTheReleaseRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "providers_fold", "registry-1.0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var captured []configs.Provider
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatal(err)
	}
	golden := map[string]configs.Provider{}
	for _, p := range captured {
		golden[strings.ToLower(p.Name)] = p
	}
	for _, release := range []string{"1.0.1", "1.0.2"} {
		t.Run(release, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
			t.Cleanup(func() { _ = ReloadProviderRegistry() })
			fixture := filepath.Join("..", "config", "testdata", "providers-fold", release)
			for _, name := range []string{"config.yaml", "custom-providers.json"} {
				data, err := os.ReadFile(filepath.Join(fixture, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(home, "config.yaml")
			overlayPath := filepath.Join(home, "custom-providers.json")
			files := func() [][]byte {
				t.Helper()
				var out [][]byte
				for _, path := range []string{configPath, overlayPath} {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, data)
				}
				return out
			}
			registry := func(stage string) map[string]configs.Provider {
				t.Helper()
				cfg, err := config.LoadRuntimeV8File(configPath)
				if err != nil {
					t.Fatalf("%s: load: %v", stage, err)
				}
				reg, err := buildGenerationProviders(cfg)
				if err != nil {
					t.Fatalf("%s: build: %v", stage, err)
				}
				// The live path: the registry /v1/config/providers serves.
				applyGenerationProviders(reg)
				snapshot, _, _ := providerRegistrySnapshot()
				out := map[string]configs.Provider{}
				for _, p := range snapshot.Providers {
					if key := strings.ToLower(p.Name); golden[key].Name != "" {
						out[key] = p
					}
				}
				return out
			}

			before := files()
			assertSameRegistry(t, "before the upgrade", registry("before"), golden)

			result, err := config.MigrateV9(context.Background(), config.MigrateV9Input{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("MigrateV9: %v", err)
			}
			fold := result.ProvidersFold
			if fold == nil || fold.Refused == "" || len(fold.Conflicts) != 1 {
				t.Fatalf("ProvidersFold = %+v, want the fold refused for acme-gw", fold)
			}
			wantInUse := map[string]string{
				"profile_id": "config.yaml", "base_url": "config.yaml", "request_path_overrides.chat": "config.yaml",
				"extra_headers.X-B11-Config": "custom-providers.json",
			}
			if got := fold.Conflicts[0].InUse; !reflect.DeepEqual(got, wantInUse) {
				t.Errorf("in use = %v, want %v", got, wantInUse)
			}
			wantLater := []config.ProviderFields{{Provider: "openai", Fields: []string{"extra_headers.X-B11-A", "extra_headers.X-B11-B"}}}
			if !reflect.DeepEqual(fold.HeadersAfterFold, wantLater) {
				t.Errorf("headers after the fold = %+v, want %+v", fold.HeadersAfterFold, wantLater)
			}
			if after := files(); !slices.EqualFunc(after, before, bytes.Equal) {
				t.Fatal("the refused fold changed config.yaml or the overlay")
			}
			assertSameRegistry(t, "after the upgrade", registry("after"), golden)

			// The operator keeps config.yaml's values and folds the rest.
			if err := os.WriteFile(overlayPath, []byte(providersFoldOverlayResolved), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err = config.MigrateV9(context.Background(), config.MigrateV9Input{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("MigrateV9 after the resolution: %v", err)
			}
			fold = result.ProvidersFold
			if fold == nil || fold.Refused != "" || fold.Retired == "" {
				t.Fatalf("ProvidersFold = %+v, want the overlay folded and retired", fold)
			}
			wantLater = []config.ProviderFields{
				{Provider: "acme-gw", Fields: []string{"extra_headers.X-B11-Config"}},
				{Provider: "openai", Fields: []string{"extra_headers.X-B11-A", "extra_headers.X-B11-B"}},
			}
			if !reflect.DeepEqual(fold.HeadersAfterFold, wantLater) {
				t.Errorf("headers after the fold = %+v, want %+v", fold.HeadersAfterFold, wantLater)
			}
			want := map[string]configs.Provider{}
			for key, p := range golden {
				want[key] = p
			}
			openai, acme := want["openai"], want["acme-gw"]
			openai.ExtraHeaders = map[string]string{"X-B11-A": "dummy-a", "X-B11-B": "dummy-b"}
			acme.ExtraHeaders = map[string]string{"X-B11-Config": "dummy-config", "X-B11-Legacy": "dummy-legacy"}
			want["openai"], want["acme-gw"] = openai, acme
			assertSameRegistry(t, "after the fold", registry("folded"), want)
		})
	}
}

// assertSameRegistry compares two registries provider by provider and field
// by field (as /v1/config/providers renders them); list fields compare as
// sets, since a fold may order a union differently.
func assertSameRegistry(t *testing.T, stage string, got, want map[string]configs.Provider) {
	t.Helper()
	fields := func(p configs.Provider) map[string]any {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		for key, value := range out {
			if list, ok := value.([]any); ok {
				slices.SortFunc(list, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
				out[key] = list
			}
		}
		return out
	}
	for _, name := range []string{"openai", "acme-gw"} {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s: the registry has no %s provider", stage, name)
			continue
		}
		gf, wf := fields(g), fields(want[name])
		for key := range wf {
			if _, ok := gf[key]; !ok {
				gf[key] = nil
			}
		}
		for _, key := range slices.Sorted(maps.Keys(gf)) {
			if !reflect.DeepEqual(gf[key], wf[key]) {
				t.Errorf("%s: %s.%s = %v, want %v", stage, name, key, gf[key], wf[key])
			}
		}
	}
}
