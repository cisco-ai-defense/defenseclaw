// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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

type observabilityV8ParityCorpus struct {
	SchemaVersion int `yaml:"schema_version"`
	Cases         []struct {
		Name   string `yaml:"name"`
		Valid  bool   `yaml:"valid"`
		Source string `yaml:"source"`
	} `yaml:"cases"`
}

func TestObservabilityV8SharedValidationCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "observability_v8", "config_validation_cases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus observabilityV8ParityCorpus
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || len(corpus.Cases) < 15 {
		t.Fatalf("unexpected parity corpus metadata: version=%d cases=%d", corpus.SchemaVersion, len(corpus.Cases))
	}
	seen := make(map[string]struct{}, len(corpus.Cases))
	for _, test := range corpus.Cases {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" {
				t.Fatal("parity case name is empty")
			}
			if _, duplicate := seen[test.Name]; duplicate {
				t.Fatalf("duplicate parity case %q", test.Name)
			}
			seen[test.Name] = struct{}{}
			_, err := ParseCompileObservabilityV8(
				"parity-case.yaml",
				[]byte(test.Source),
				ObservabilityV8CompileOptions{DefaultDataDir: "/var/lib/defenseclaw"},
			)
			if test.Valid && err != nil {
				t.Fatalf("Go rejected shared valid case: %v", err)
			}
			if !test.Valid && err == nil {
				t.Fatal("Go accepted shared invalid case")
			}
		})
	}
}
