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

package extproc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVerdictClient(t *testing.T) {
	var got VerdictRequest
	answer := `{"action":"block","severity":"HIGH","reason":"matched","source":"asset_policy","rule_ids":["R1"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != VerdictPath || r.Header.Get("Authorization") != "Bearer tok-1" ||
			r.Header.Get("X-DefenseClaw-Client") == "" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewVerdictClient(JudgeConfig{URL: srv.URL + VerdictPath, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	call := ToolCall{Actor: ActorRef{Atespace: "a4-gv", Name: "p1", UID: "u1"}, Host: "mcp.x", Server: "tickets", Tool: "run",
		Args: json.RawMessage(`{"a":1}`)}
	v, err := c.JudgeToolCall(context.Background(), call)
	if err != nil || !v.Block || v.Reason != "matched" || len(v.Findings) != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	if got.Actor != (VerdictActor{"a4-gv", "p1", "u1"}) || got.MCP.Host != "mcp.x" || got.MCP.Server != "tickets" ||
		got.MCP.Tool != "run" || string(got.MCP.Arguments) != `{"a":1}` {
		t.Fatalf("request: %+v", got)
	}
	answer = `{"action":"alert"}`
	if v, err := c.JudgeToolCall(context.Background(), call); err != nil || v.Block || !v.Alert {
		t.Fatalf("alert: %+v %v", v, err)
	}
	answer = `{"action":"maybe"}`
	if _, err := c.JudgeToolCall(context.Background(), call); err == nil {
		t.Fatal("unknown action accepted")
	}
	if c, err := NewVerdictClient(JudgeConfig{}); c != nil || err != nil {
		t.Fatalf("empty URL: %v %v", c, err)
	}
	bad, _ := NewVerdictClient(JudgeConfig{URL: srv.URL + "/nope"})
	if _, err := bad.JudgeToolCall(context.Background(), call); err == nil {
		t.Fatal("HTTP error not reported")
	}
}
