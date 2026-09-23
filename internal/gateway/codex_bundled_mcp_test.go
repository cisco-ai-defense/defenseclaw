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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func writeCodexBundledMCPFixture(t *testing.T) string {
	t.Helper()
	codexHome := filepath.Join(t.TempDir(), "codex-home")
	t.Setenv("CODEX_HOME", codexHome)
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `[mcp_servers.openaiDeveloperDocs]
url = "https://developers.openai.com/mcp"

[mcp_servers.node_repl]
command = "node_repl"

[mcp_servers.operator]
url = "https://example.test/mcp"
`
	path := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodexMCPEntryScanTargetsExcludeOnlyBundledEntry(t *testing.T) {
	path := writeCodexBundledMCPFixture(t)

	targets := codexMCPEntryScanTargets([]string{path})
	got := strings.Join(targets, "\n")
	if strings.Contains(got, "developers.openai.com/mcp") {
		t.Fatalf("bundled developer docs reached component scan targets: %v", targets)
	}
	for _, want := range []string{"node_repl", "https://example.test/mcp"} {
		if !strings.Contains(got, want) {
			t.Fatalf("component scan targets = %v, missing %q", targets, want)
		}
	}
}

func TestCodexMCPEntryScanTargetsDoNotTrustProjectSpoof(t *testing.T) {
	_ = writeCodexBundledMCPFixture(t)
	projectConfig := filepath.Join(t.TempDir(), ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(projectConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectConfig, []byte(`[mcp_servers.openaiDeveloperDocs]
url = "https://developers.openai.com/mcp"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	targets := codexMCPEntryScanTargets([]string{projectConfig})
	if len(targets) != 1 || targets[0] != "https://developers.openai.com/mcp" {
		t.Fatalf("project spoof targets = %v, want scan-eligible docs URL", targets)
	}
}

func TestHandleMCPScanRejectsBundledNamedEntry(t *testing.T) {
	_ = writeCodexBundledMCPFixture(t)
	body, err := json.Marshal(mcpScanRequest{Target: "openaiDeveloperDocs"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()

	(&APIServer{scannerCfg: &config.Config{}}).handleMCPScan(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "discovery-only") {
		t.Fatalf("response = %q, want bundled discovery-only refusal", w.Body.String())
	}
}
