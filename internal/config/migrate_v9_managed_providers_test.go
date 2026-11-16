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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// #1099: on a managed host the admin config owns llm_providers. A local
// custom-providers.json that names an admin provider again is neither merged
// into the admin config nor retired, so a 1.0.1 or 1.0.2 admin config
// (config_version 9) upgrades byte for byte unchanged, and a v8 admin config
// migrates with its provider fields exactly as the admin wrote them.
func TestMigrateV9ManagedKeepsTheAdminProviders(t *testing.T) {
	const providers = "llm_providers:\n  custom:\n  - name: openai\n    domains: [llm.acme.internal]\n" +
		"    env_keys: [ACME_KEY]\n    extra_headers:\n      X-Team: sec\n"
	const overlay = `{"providers":[{"name":"OpenAI","domains":["eu.llm.acme.internal"],"env_keys":["ACME_EU_KEY"],
  "extra_headers":{"X-Route":"eu"}}]}`
	setup := func(t *testing.T, version string) (dir, configPath, overlayPath string, source []byte) {
		t.Helper()
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		dir = t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		configPath = filepath.Join(dir, "config.yaml")
		source = []byte("config_version: " + version + "\ndata_dir: " + dir + "\n" + providers + "observability: {}\n")
		if err := os.WriteFile(configPath, source, 0o600); err != nil {
			t.Fatal(err)
		}
		overlayPath = filepath.Join(dir, ProvidersOverlayFile)
		if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, configPath, overlayPath, source
	}

	t.Run("config_version 9 admin config", func(t *testing.T) {
		_, configPath, overlayPath, source := setup(t, "9")
		result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, Managed: true})
		if err != nil {
			t.Fatalf("MigrateV9: %v", err)
		}
		if !bytes.Equal(result.Migrated, source) || len(result.Written) != 0 {
			t.Fatalf("a managed v9 admin config was rewritten (written %v):\n%s", result.Written, result.Migrated)
		}
		if got, err := os.ReadFile(configPath); err != nil || !bytes.Equal(got, source) {
			t.Fatalf("admin config.yaml changed (%v):\n%s", err, got)
		}
		if got, err := os.ReadFile(overlayPath); err != nil || string(got) != overlay {
			t.Fatalf("the local overlay changed (%v):\n%s", err, got)
		}
	})

	t.Run("config_version 8 admin config", func(t *testing.T) {
		_, configPath, overlayPath, _ := setup(t, "8")
		result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, Managed: true})
		if err != nil {
			t.Fatalf("MigrateV9: %v", err)
		}
		var got struct {
			LLMProviders struct {
				Custom []map[string]any `yaml:"custom"`
			} `yaml:"llm_providers"`
		}
		if err := yaml.Unmarshal(result.Migrated, &got); err != nil {
			t.Fatal(err)
		}
		want := []map[string]any{{
			"name": "openai", "domains": []any{"llm.acme.internal"}, "env_keys": []any{"ACME_KEY"},
			"extra_headers": map[string]any{"X-Team": "sec"},
		}}
		if !reflect.DeepEqual(got.LLMProviders.Custom, want) {
			t.Fatalf("admin llm_providers.custom =\n  %v\nwant\n  %v\n%s", got.LLMProviders.Custom, want, result.Migrated)
		}
		if notes := strings.Join(result.Record.Notes, "\n"); !strings.Contains(notes, "is a local provider overlay") {
			t.Errorf("the record does not say the local overlay stays: %q", notes)
		}
		if got, err := os.ReadFile(overlayPath); err != nil || string(got) != overlay {
			t.Fatalf("the managed migration retired or changed the local overlay (%v):\n%s", err, got)
		}
	})
}
