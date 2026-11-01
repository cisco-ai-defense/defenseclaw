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

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestLoadFoldsAnAliasedConnectorSelection pins GAP-2007: the loader folds
// guardrail.connector and claw.mode to the registry name, so no reader of the
// loaded config sees claude-code, claude_code or a mixed-case name.
func TestLoadFoldsAnAliasedConnectorSelection(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"claude-code", "claudecode"},
		{"claude_code", "claudecode"},
		{"Claude-Code", "claudecode"},
		{"claudecode", "claudecode"},
		{"Codex", "codex"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			testenv.SetHome(t, t.TempDir())
			path := filepath.Join(t.TempDir(), DefaultConfigName)
			body := "config_version: 9\nclaw:\n  mode: " + tc.raw + "\nguardrail:\n  enabled: true\n  connector: " + tc.raw + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Guardrail.Connector != tc.want {
				t.Errorf("guardrail.connector = %q, want %q", cfg.Guardrail.Connector, tc.want)
			}
			if string(cfg.Claw.Mode) != tc.want {
				t.Errorf("claw.mode = %q, want %q", cfg.Claw.Mode, tc.want)
			}
		})
	}
}
