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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0581: `config-v8 validate`, the validator behind `defenseclaw config
// set`, setup and the TUI, refuses every invalid guardrail.cascade that
// config.ValidateCandidate (the Go writers) refuses: one check, the review's
// four candidates.
func TestConfigV8ValidateRefusesInvalidCascade(t *testing.T) {
	for name, body := range map[string]string{
		"lock violation (profile block_at)":  "guardrail:\n  cascade:\n    admin:\n      locked: [block_at]\n  profiles:\n    p:\n      block_at: CRITICAL\n",
		"lock violation (connector unknown)": "guardrail:\n  cascade:\n    admin:\n      locked: [unknown]\n  connectors:\n    codex:\n      cascade:\n        unknown: block\n",
		"unknown allow":                      "guardrail:\n  cascade:\n    unknown: allow\n",
		// A lane name no release defines. "effects" was used here until the
		// engine train made it a real lane (GAP-2097).
		"no such lane": "guardrail:\n  cascade:\n    lanes:\n      no-such-lane-in-any-release: on\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("DEFENSECLAW_HOME", filepath.Join(dir, ".defenseclaw"))
			path := filepath.Join(dir, "config.yaml")
			src := "config_version: 9\ndata_dir: " + dir + "\n" + body
			if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := checkConfigV8Candidate(path, dir)
			goErr := config.ValidateCandidate(path, []byte(src))
			if err == nil || goErr == nil {
				t.Fatalf("config-v8 validate: %v; ValidateCandidate: %v; both must refuse", err, goErr)
			}
		})
	}
	// A valid cascade passes both.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(dir, ".defenseclaw"))
	path := filepath.Join(dir, "config.yaml")
	src := "config_version: 9\ndata_dir: " + dir + "\nguardrail:\n  cascade:\n    unknown: block\n    admin:\n      locked: [block_at]\n  profiles:\n    p:\n      mode: observe\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkConfigV8Candidate(path, dir); err != nil {
		t.Fatalf("valid cascade refused: %v", err)
	}
}
