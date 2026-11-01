// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// BenchmarkBenignRedirectHook measures a benign partial Bash redirect through
// both default hook routes. Unique tool IDs keep each iteration a fresh call.
func BenchmarkBenignRedirectHook(b *testing.B) {
	for _, connector := range []string{"claudecode", "codex"} {
		b.Run(connector, func(b *testing.B) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				n++
				payload := []byte(fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"bench","cwd":"/tmp","tool_name":"Bash","tool_use_id":"toolu_bench_%d","tool_input":{"command":"bash -i >& /tmp/session.log 0>&1"}}`, n))
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", bytes.NewReader(payload))
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"allow"`)) {
					b.Fatalf("status %d: %.300s", recorder.Code, recorder.Body.String())
				}
			}
		})
	}
}
