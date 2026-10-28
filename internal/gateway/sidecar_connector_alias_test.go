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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestSingleConnectorBootResolvesAnAliasedPrimary pins GAP-2007 (and the
// end-to-end GAP-1971/GAP-1972 path): a single-connector config whose
// guardrail.connector is an alias (what the CLI roster prune leaves) must
// boot the connector, label it by its registry name and evaluate its hooks.
// Before, the boot read the raw name and failed "not found in registry", so
// the hooks failed open.
func TestSingleConnectorBootResolvesAnAliasedPrimary(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"claude-code", "claudecode"},
		{"claude_code", "claudecode"},
		{"claudecode", "claudecode"},
		{"Codex", "codex"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			testenv.SetHome(t, t.TempDir())
			path := filepath.Join(t.TempDir(), config.DefaultConfigName)
			body := "config_version: 9\nguardrail:\n  enabled: true\n  connector: " + tc.raw + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadFromFile(path)
			if err != nil {
				t.Fatal(err)
			}
			name := configuredConnectorName(cfg)
			if name != tc.want {
				t.Errorf("configuredConnectorName() = %q, want %q", name, tc.want)
			}
			conn, err := resolveActiveConnector(connector.NewDefaultRegistry(), name, "test")
			if err != nil || conn == nil || conn.Name() != tc.want {
				t.Fatalf("resolveActiveConnector(%q) = %v, %v; want %s", name, conn, err, tc.want)
			}
			if got := connectorNameForConfig(cfg); got != tc.want {
				t.Errorf("connectorNameForConfig() = %q, want %q", got, tc.want)
			}
			api := &APIServer{scannerCfg: cfg}
			if got := api.claudeCodeEnabled(); got != (tc.want == "claudecode") {
				t.Errorf("claudeCodeEnabled() = %v", got)
			}
			if got := api.codexEnabled(); got != (tc.want == "codex") {
				t.Errorf("codexEnabled() = %v", got)
			}
		})
	}
}
