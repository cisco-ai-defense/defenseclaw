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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPatchYAMLFileStringLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	initial := "# keep me\nopenshell:\n  enabled: true\n  egress:\n    allow: [old.example] # inline\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PatchYAMLFile(path, map[string]any{
		"openshell.egress.allow": []string{"old.example", "new.example"},
		"openshell.egress.block": []string{"paste.example"},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenShell struct {
			Enabled bool `yaml:"enabled"`
			Egress  struct {
				Allow []string `yaml:"allow"`
				Block []string `yaml:"block"`
			} `yaml:"egress"`
		} `yaml:"openshell"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("patched YAML invalid: %v\n%s", err, raw)
	}
	eg := doc.OpenShell.Egress
	if !doc.OpenShell.Enabled || len(eg.Allow) != 2 || eg.Allow[1] != "new.example" || len(eg.Block) != 1 {
		t.Fatalf("patched = %+v\n%s", doc, raw)
	}
	if !strings.Contains(string(raw), "# keep me") || !strings.Contains(string(raw), "# inline") {
		t.Fatalf("comments lost:\n%s", raw)
	}
}
