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

// TestSandboxFloorSharedValidationCorpus loads every case of the corpus the
// Python loader is also tested against
// (cli/tests/test_config_sandbox_profiles_parity.py). The verdict is the
// daemon's loader (LoadRuntimeV8File: schema and validation); the message is
// LoadFromFile's (validation without the schema), which must carry the
// case's error verbatim, as Python's does.
func TestSandboxFloorSharedValidationCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sandbox_floor_cases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int `yaml:"schema_version"`
		Cases         []struct {
			Name   string `yaml:"name"`
			Valid  bool   `yaml:"valid"`
			Error  string `yaml:"error"`
			Source string `yaml:"source"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || len(corpus.Cases) < 15 {
		t.Fatalf("unexpected corpus metadata: version=%d cases=%d", corpus.SchemaVersion, len(corpus.Cases))
	}
	seen := map[string]bool{}
	for _, tc := range corpus.Cases {
		if tc.Name == "" || seen[tc.Name] || tc.Valid == (tc.Error != "") {
			t.Fatalf("corpus case %q: empty or duplicated name, or valid and error disagree", tc.Name)
		}
		seen[tc.Name] = true
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, DefaultConfigName)
			if err := os.WriteFile(path, []byte(tc.Source+"data_dir: "+dir+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, runtimeErr := LoadRuntimeV8File(path)
			_, loadErr := LoadFromFile(path)
			if tc.Valid {
				if runtimeErr != nil || loadErr != nil {
					t.Fatalf("a shared valid case was refused: runtime %v; load %v", runtimeErr, loadErr)
				}
				return
			}
			if runtimeErr == nil {
				t.Fatal("the daemon's loader accepted a shared invalid case")
			}
			if loadErr == nil || !strings.Contains(loadErr.Error(), tc.Error) {
				t.Fatalf("LoadFromFile = %v, want %q", loadErr, tc.Error)
			}
		})
	}
}
