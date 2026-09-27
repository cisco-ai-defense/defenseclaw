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
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenShellSharedValidationCorpus loads every case of the corpus the
// Python writer is also tested against (cli/tests/test_config_openshell.py).
func TestOpenShellSharedValidationCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "openshell", "config_validation_cases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int `yaml:"schema_version"`
		Cases         []struct {
			Name   string `yaml:"name"`
			Valid  bool   `yaml:"valid"`
			Source string `yaml:"source"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || len(corpus.Cases) < 20 {
		t.Fatalf("unexpected corpus metadata: version=%d cases=%d", corpus.SchemaVersion, len(corpus.Cases))
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, tc := range corpus.Cases {
		if tc.Name == "" || seen[tc.Name] {
			t.Fatalf("corpus case name %q is empty or duplicated", tc.Name)
		}
		seen[tc.Name] = true
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, DefaultConfigName)
			if err := os.WriteFile(path, []byte(tc.Source+"data_dir: "+dir+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFromFile(path)
			if tc.Valid && err != nil {
				t.Fatalf("Go rejected a shared valid case: %v", err)
			}
			if !tc.Valid && err == nil {
				t.Fatal("Go accepted a shared invalid case")
			}
			if err != nil {
				t.Logf("rejected: %v", err)
			}
		})
	}
}
