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

func TestInspectToolClient(t *testing.T) {
	var got inspectToolRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/inspect/tool" || r.Header.Get("Authorization") != "Bearer tok-1" ||
			r.Header.Get("X-DefenseClaw-Client") == "" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"action":"block","severity":"HIGH","reason":"matched","findings":["R1"]}`))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewInspectToolClient(JudgeConfig{URL: srv.URL + "/api/v1/inspect/tool", TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.JudgeToolCall(context.Background(), ToolCall{Server: "my server", Tool: "run", Args: json.RawMessage(`{"a":1}`)})
	if err != nil || !v.Block || v.Reason != "matched" {
		t.Fatalf("%+v %v", v, err)
	}
	if got.Tool != "mcp__my_server__run" || got.MCPServerName != "my server" || string(got.Args) != `{"a":1}` {
		t.Fatalf("request: %+v", got)
	}
	if c, err := NewInspectToolClient(JudgeConfig{}); c != nil || err != nil {
		t.Fatalf("empty URL: %v %v", c, err)
	}
	bad, _ := NewInspectToolClient(JudgeConfig{URL: srv.URL + "/nope"})
	if _, err := bad.JudgeToolCall(context.Background(), ToolCall{Server: "s", Tool: "t"}); err == nil {
		t.Fatal("HTTP error not reported")
	}
}
