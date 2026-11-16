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

package config

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// providersFoldHome copies testdata/providers-fold/<release> (a config.yaml
// that release wrote and a legacy custom-providers.json the operator put next
// to it) into a new data home.
func providersFoldHome(t *testing.T, release string) string {
	t.Helper()
	fixture, err := filepath.Abs(filepath.Join("testdata", "providers-fold", release))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	copyUpgradeFixture(t, fixture, home)
	return home
}

// GAP-0163: the legacy overlay sets acme-gw fields that config.yaml, written
// by 1.0.1 or 1.0.2, sets to other values. The gateway used config.yaml's
// values, so folding the file's would change the provider in use, and
// dropping them would lose what the operator wrote. The migration folds
// nothing: both files stay byte for byte, and it names each field (never a
// value: a header may hold a credential).
func TestMigrateV9RefusesAConflictingLegacyOverlayOnAV9Config(t *testing.T) {
	for _, release := range []string{"1.0.1", "1.0.2"} {
		t.Run(release, func(t *testing.T) {
			home := providersFoldHome(t, release)
			configPath := filepath.Join(home, "config.yaml")
			before := upgradeFixtureTree(t, home)
			for _, dryRun := range []bool{true, false} {
				result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DryRun: dryRun})
				if err != nil {
					t.Fatalf("dry run %v: MigrateV9: %v", dryRun, err)
				}
				if after := upgradeFixtureTree(t, home); !maps.Equal(before, after) {
					t.Fatalf("dry run %v: the home changed:\nbefore %v\nafter  %v", dryRun, before, after)
				}
				if len(result.Written) != 0 {
					t.Errorf("dry run %v: wrote %v, want nothing", dryRun, result.Written)
				}
				fold := result.ProvidersFold
				if fold == nil || fold.Refused == "" {
					t.Fatalf("dry run %v: ProvidersFold = %+v, want a refused fold", dryRun, fold)
				}
				if len(fold.Conflicts) != 1 || fold.Conflicts[0].Provider != "acme-gw" {
					t.Fatalf("dry run %v: conflicts = %+v, want acme-gw only", dryRun, fold.Conflicts)
				}
				got := slices.Sorted(slices.Values(fold.Conflicts[0].Fields))
				want := []string{"base_url", "extra_headers.X-B11-Config", "profile_id", "request_path_overrides.chat"}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("dry run %v: conflicting fields = %v, want %v", dryRun, got, want)
				}
				wantInUse := map[string]string{"profile_id": "config.yaml", "base_url": "config.yaml",
					"request_path_overrides.chat": "config.yaml", "extra_headers.X-B11-Config": "custom-providers.json"}
				if got := fold.Conflicts[0].InUse; !reflect.DeepEqual(got, wantInUse) {
					t.Errorf("dry run %v: in use = %v, want %v (1.0.2 sent the file's header, GAP-0184)", dryRun, got, wantInUse)
				}
				wantLater := []ProviderFields{{Provider: "openai", Fields: []string{"extra_headers.X-B11-A", "extra_headers.X-B11-B"}}}
				if !reflect.DeepEqual(fold.HeadersAfterFold, wantLater) {
					t.Errorf("dry run %v: headers after the fold = %+v, want %+v", dryRun, fold.HeadersAfterFold, wantLater)
				}
				for _, part := range []string{"acme-gw (", "config.yaml's value is in use",
					"extra_headers.X-B11-Config: the file's value is in use", "Neither file was changed",
					"no value in use changed", "defenseclaw migrate",
					"the gateway then also sends extra_headers it does not send now: openai (extra_headers.X-B11-A, extra_headers.X-B11-B)"} {
					if !strings.Contains(fold.Refused, part) {
						t.Errorf("dry run %v: refusal %q does not say %q", dryRun, fold.Refused, part)
					}
				}
				for _, value := range []string{"dummy-legacy-wins", "dummy-config", "b11-acme-legacy"} {
					if strings.Contains(fold.Refused, value) {
						t.Errorf("dry run %v: refusal %q prints the value %q", dryRun, fold.Refused, value)
					}
				}
				if fold.Retired != "" || len(fold.Folded) != 0 {
					t.Errorf("dry run %v: refused fold reports folded %v, retired %q", dryRun, fold.Folded, fold.Retired)
				}
			}
		})
	}
}

// GAP-0163: once the operator keeps config.yaml's values (the conflicting
// fields leave the file), the migration of a 1.0.1- or 1.0.2-written config
// folds the rest of the legacy overlay into llm_providers.custom: the lists
// gain the file's items, the maps its keys, and a new provider and Ollama
// port are added. The file is retired next to the one an earlier migration
// retired, putting back the data home copy (the installer's rollback) undoes
// it, and the next run folds the same way.
func TestMigrateV9FoldsALegacyOverlayIntoAV9Config(t *testing.T) {
	overlay := `{"providers":[
  {"name":"ACME-GW","domains":["b11-acme-alt.example.test","b11-acme.example.test"],"env_keys":["B11_ACME_LEGACY_DUMMY_KEY"],
   "base_url":"https://b11-acme.example.test/v1","request_path_overrides":{"chat":"/acme/chat","legacy":"/legacy/only"},
   "extra_headers":{"X-B11-Legacy":"dummy-legacy"}},
  {"name":"b11-new","domains":["b11-new.example.test"],"env_keys":["B11_NEW_KEY"]}
 ],"ollama_ports":[11500]}`
	for _, release := range []string{"1.0.1", "1.0.2"} {
		t.Run(release, func(t *testing.T) {
			home := providersFoldHome(t, release)
			configPath := filepath.Join(home, "config.yaml")
			overlayPath := filepath.Join(home, ProvidersOverlayFile)
			if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
				t.Fatal(err)
			}
			earlier := overlayPath + DataJSONMigratedSuffix
			if err := os.WriteFile(earlier, []byte(`{"providers":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			original, err := LoadRuntimeV8FromBytes(configPath, source)
			if err != nil {
				t.Fatalf("this release refuses the %s config: %v", release, err)
			}
			before := upgradeFixtureTree(t, home)

			preview, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DryRun: true})
			if err != nil {
				t.Fatalf("dry run: %v", err)
			}
			if after := upgradeFixtureTree(t, home); !maps.Equal(before, after) {
				t.Fatal("the dry run changed the home")
			}

			fold := func(stage string) []byte {
				t.Helper()
				result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
				if err != nil {
					t.Fatalf("%s: MigrateV9: %v", stage, err)
				}
				f := result.ProvidersFold
				if f == nil || f.Refused != "" || !reflect.DeepEqual(f.Folded, []string{"acme-gw", "b11-new"}) {
					t.Fatalf("%s: ProvidersFold = %+v, want acme-gw and b11-new folded", stage, f)
				}
				if f.Retired != earlier+".2" {
					t.Errorf("%s: retired to %q, want %q (the earlier retired file keeps its name)", stage, f.Retired, earlier+".2")
				}
				if raw, err := os.ReadFile(earlier); err != nil || string(raw) != `{"providers":[]}` {
					t.Errorf("%s: the earlier retired file = %q (%v)", stage, raw, err)
				}
				if raw, err := os.ReadFile(f.Retired); err != nil || string(raw) != overlay {
					t.Errorf("%s: the retired file does not hold the overlay: %q (%v)", stage, raw, err)
				}
				if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
					t.Errorf("%s: %s is still a live input: %v", stage, overlayPath, err)
				}
				for _, path := range []string{configPath, f.Retired} {
					if !slices.Contains(result.Written, path) {
						t.Errorf("%s: written %v lacks %s", stage, result.Written, path)
					}
				}
				raw, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if string(raw) != string(preview.Migrated) {
					t.Errorf("%s: config.yaml differs from the dry run:\n%s\n---\n%s", stage, raw, preview.Migrated)
				}
				return raw
			}
			first := fold("fold")
			wantLater := []ProviderFields{
				{Provider: "ACME-GW", Fields: []string{"extra_headers.X-B11-Config"}},
				{Provider: "openai", Fields: []string{"extra_headers.X-B11-A", "extra_headers.X-B11-B"}},
			}
			if !reflect.DeepEqual(preview.ProvidersFold.HeadersAfterFold, wantLater) {
				t.Errorf("headers after the fold = %+v, want %+v", preview.ProvidersFold.HeadersAfterFold, wantLater)
			}
			if !slices.ContainsFunc(preview.ProvidersFold.Notes, func(note string) bool {
				return strings.Contains(note, "the gateway also sends ACME-GW (extra_headers.X-B11-Config); openai (")
			}) {
				t.Errorf("the fold notes %q do not name the headers sent from now on", preview.ProvidersFold.Notes)
			}
			cfg, err := LoadRuntimeV8FromBytes(configPath, first)
			if err != nil {
				t.Fatalf("load the folded config: %v\n%s", err, first)
			}
			custom := cfg.LLMProviders.Custom
			if len(custom) != 3 {
				t.Fatalf("llm_providers.custom has %d entries, want 3:\n%s", len(custom), first)
			}
			if !reflect.DeepEqual(custom[0], original.LLMProviders.Custom[0]) {
				t.Errorf("openai changed:\n  %+v\nwant\n  %+v", custom[0], original.LLMProviders.Custom[0])
			}
			wantACME := original.LLMProviders.Custom[1]
			wantACME.Domains = []string{"b11-acme.example.test", "b11-acme-alt.example.test"}
			wantACME.EnvKeys = []string{"B11_ACME_DUMMY_KEY", "B11_ACME_LEGACY_DUMMY_KEY"}
			wantACME.RequestPathOverrides = map[string]string{"chat": "/acme/chat", "responses": "/acme/responses", "legacy": "/legacy/only"}
			wantACME.ExtraHeaders = map[string]string{"X-B11-Config": "dummy-config", "X-B11-Legacy": "dummy-legacy"}
			if !reflect.DeepEqual(custom[1], wantACME) {
				t.Errorf("acme-gw =\n  %+v\nwant\n  %+v", custom[1], wantACME)
			}
			if got := custom[2]; got.Name != "b11-new" || !reflect.DeepEqual(got.Domains, []string{"b11-new.example.test"}) ||
				!reflect.DeepEqual(got.EnvKeys, []string{"B11_NEW_KEY"}) {
				t.Errorf("b11-new = %+v", got)
			}
			if got := cfg.LLMProviders.OllamaPorts; !reflect.DeepEqual(got, []int{11500}) {
				t.Errorf("ollama_ports = %v, want [11500]", got)
			}

			// Nothing is left to fold.
			again, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err != nil || again.ProvidersFold != nil || len(again.Written) != 0 {
				t.Fatalf("second run: fold %+v, written %v, err %v; want nothing", again.ProvidersFold, again.Written, err)
			}

			restoreUpgradeFixture(t, home, before)
			if after := upgradeFixtureTree(t, home); !maps.Equal(before, after) {
				t.Fatal("rollback: the home differs from the copy taken before the fold")
			}
			if second := fold("re-fold"); string(second) != string(first) {
				t.Errorf("the fold after a rollback differs:\n%s\n---\n%s", second, first)
			}
		})
	}
}

// GAP-0163: a config_version 8 config whose llm_providers.custom sets a
// field the legacy overlay sets to another value migrates to 9 without the
// overlay's providers; the overlay stays a live input, unchanged, and the
// record and the result name the fields.
func TestMigrateV9KeepsAConflictingOverlayOutOfAV8Migration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nllm_providers:\n  custom:\n  - name: acme\n    domains: [llm.acme.internal]\n" +
		"    base_url: https://llm.acme.internal/v1\n    extra_headers:\n      X-Team: sec\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := `{"providers":[{"name":"ACME","domains":["eu.llm.acme.internal"],"base_url":"https://eu.llm.acme.internal/v1",
  "extra_headers":{"X-Team":"eu","X-Route":"eu"}}]}`
	overlayPath := filepath.Join(dir, ProvidersOverlayFile)
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	cfg, err := LoadRuntimeV8FromBytes(configPath, result.Migrated)
	if err != nil {
		t.Fatal(err)
	}
	want := []LLMCustomProvider{{Name: "acme", Domains: []string{"llm.acme.internal"}, BaseURL: "https://llm.acme.internal/v1",
		ExtraHeaders: map[string]string{"X-Team": "sec"}}}
	if got := cfg.LLMProviders.Custom; !reflect.DeepEqual(got, want) {
		t.Errorf("llm_providers.custom = %+v, want config's entry only: %+v", got, want)
	}
	if raw, err := os.ReadFile(overlayPath); err != nil || string(raw) != overlay {
		t.Errorf("the overlay changed or moved: %q (%v)", raw, err)
	}
	fold := result.ProvidersFold
	if fold == nil || len(fold.Conflicts) != 1 ||
		!reflect.DeepEqual(slices.Sorted(slices.Values(fold.Conflicts[0].Fields)), []string{"base_url", "extra_headers.X-Team"}) {
		t.Fatalf("ProvidersFold = %+v, want acme base_url and extra_headers.X-Team", fold)
	}
	if want := map[string]string{"base_url": "config.yaml", "extra_headers.X-Team": "custom-providers.json"}; !reflect.DeepEqual(fold.Conflicts[0].InUse, want) {
		t.Errorf("in use = %v, want %v", fold.Conflicts[0].InUse, want)
	}
	if !slices.ContainsFunc(result.Record.Notes, func(note string) bool { return note == fold.Refused }) {
		t.Errorf("the record notes %q lack the refusal %q", result.Record.Notes, fold.Refused)
	}
	for _, move := range result.Record.Moved {
		if move.Source == ProvidersOverlayFile {
			t.Errorf("the record moves %+v from the refused overlay", move)
		}
	}
}

// GAP-0163: a tls block config.yaml and the overlay both set agrees when the
// CA file config.yaml names holds the overlay's CA bundle; then nothing
// conflicts and config.yaml keeps its file.
func TestMigrateV9SameCABundleIsNoConflict(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	ca := filepath.Join(dir, "acme-ca.pem")
	if err := os.WriteFile(ca, []byte("acme certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 9\ndata_dir: " + dir + "\nllm_providers:\n  custom:\n  - name: acme\n    domains: [llm.acme.internal]\n" +
		"    tls:\n      ca_cert_file: " + ca + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pem      string
		conflict bool
	}{{"acme certificate", false}, {"another certificate", true}} {
		overlay := `{"providers":[{"name":"acme","env_keys":["ACME_KEY"],"tls":{"ca_cert_pem":"` + tc.pem + `"}}]}`
		if err := os.WriteFile(filepath.Join(dir, ProvidersOverlayFile), []byte(overlay), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DryRun: true})
		if err != nil {
			t.Fatalf("%s: %v", tc.pem, err)
		}
		fold := result.ProvidersFold
		if fold == nil {
			t.Fatalf("%s: no fold", tc.pem)
		}
		if got := len(fold.Conflicts) > 0; got != tc.conflict {
			t.Errorf("%s: conflict %v, want %v (%+v)", tc.pem, got, tc.conflict, fold)
		}
		if !tc.conflict && !strings.Contains(string(result.Migrated), "ca_cert_file: "+ca) {
			t.Errorf("%s: config.yaml no longer names its CA file:\n%s", tc.pem, result.Migrated)
		}
	}
}

// GAP-0184: a provider the legacy overlay names twice with different values
// for a header is not folded. Before 1.0.3 the gateway sent the first
// entry's header (a same-name merge dropped the later entry's headers), and
// the fold takes the later entry's values, so folding would change the
// header in use. A provider named like a built-in sent neither.
func TestMigrateV9RefusesAnOverlayHeaderNamedTwiceWithTwoValues(t *testing.T) {
	for _, tc := range []struct{ name, inUse string }{{"acme", "custom-providers.json"}, {"openai", "none"}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			configPath := filepath.Join(dir, "config.yaml")
			source := "config_version: 9\ndata_dir: " + dir + "\nobservability: {}\n"
			if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			overlay := `{"providers":[{"name":"` + tc.name + `","domains":["llm.acme.internal"],"extra_headers":{"X-Team":"dummy-first"}},
  {"name":"` + tc.name + `","extra_headers":{"X-Team":"dummy-later","X-Route":"eu"}}]}`
			overlayPath := filepath.Join(dir, ProvidersOverlayFile)
			if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("MigrateV9: %v", err)
			}
			fold := result.ProvidersFold
			want := []ProviderConflict{{Provider: tc.name, Fields: []string{"extra_headers.X-Team"},
				InUse: map[string]string{"extra_headers.X-Team": tc.inUse}}}
			if fold == nil || fold.Refused == "" || len(fold.Conflicts) != 0 || !reflect.DeepEqual(fold.Repeated, want) {
				t.Fatalf("ProvidersFold = %+v, want the fold refused with %+v", fold, want)
			}
			if !strings.Contains(fold.Refused, "the file sets different values for "+tc.name+" (extra_headers.X-Team: ") {
				t.Errorf("refusal %q does not name the repeated header", fold.Refused)
			}
			for _, value := range []string{"dummy-first", "dummy-later"} {
				if strings.Contains(fold.Refused, value) {
					t.Errorf("refusal %q prints the value %q", fold.Refused, value)
				}
			}
			if raw, err := os.ReadFile(configPath); err != nil || string(raw) != source {
				t.Errorf("config.yaml changed: %q (%v)", raw, err)
			}
			if raw, err := os.ReadFile(overlayPath); err != nil || string(raw) != overlay {
				t.Errorf("the overlay changed or moved: %q (%v)", raw, err)
			}
		})
	}
}
