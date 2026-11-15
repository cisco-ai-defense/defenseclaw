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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
)

func TestVerdictClient(t *testing.T) {
	var got calloutapi.Request
	answer := `{"v":"1","verdict":"deny","severity":"HIGH","reason":"matched","source":"mcp_asset_policy","findings":["R1"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != calloutapi.Path || r.Header.Get("Authorization") != "Bearer tok-1" ||
			r.Header.Get("X-DefenseClaw-Client") != calloutapi.ClientTag || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// The gateway decodes strictly: unknown fields are refused.
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewVerdictClient(JudgeConfig{URL: srv.URL + calloutapi.Path, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	call := ToolCall{Actor: ActorRef{Atespace: "a4-gv", Name: "p1", UID: "u1"}, Host: "mcp.x", Server: "tickets", Tool: "run",
		URL: "https://mcp.x/mcp", SessionID: "s-1", RequestID: "r-1", Args: json.RawMessage(`{"a":1}`)}
	v, err := c.JudgeToolCall(context.Background(), call)
	if err != nil || !v.Block || v.Ask || v.Reason != "matched" || v.Source != "mcp_asset_policy" || len(v.Findings) != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	want := calloutapi.Request{V: "1", RequestID: "r-1", Actor: calloutapi.Actor{Atespace: "a4-gv", Name: "p1"},
		MCP:  calloutapi.MCP{Server: "tickets", URL: "https://mcp.x/mcp", Transport: "http", Method: "tools/call", Tool: "run"},
		Args: json.RawMessage(`{"a":1}`), SessionID: "s-1"}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !bytes.Equal(gb, wb) {
		t.Fatalf("request\n got %s\nwant %s", gb, wb)
	}
	for _, tc := range []struct {
		answer            string
		block, ask, alert bool
	}{
		{`{"v":"1","verdict":"allow","source":"none"}`, false, false, false},
		{`{"v":"1","verdict":"allow","source":"tool_rules","findings":["F1"]}`, false, false, true},
		{`{"v":"1","verdict":"ask","source":"tool_rules","reason":"needs approval"}`, true, true, false},
	} {
		answer = tc.answer
		v, err := c.JudgeToolCall(context.Background(), call)
		if err != nil || v.Block != tc.block || v.Ask != tc.ask || v.Alert != tc.alert {
			t.Fatalf("%s: %+v %v", tc.answer, v, err)
		}
	}
	for _, bad := range []string{`{"v":"1","verdict":"block"}`, `{"v":"2","verdict":"allow"}`, `{"verdict":"allow"}`, `not json`} {
		answer = bad
		if _, err := c.JudgeToolCall(context.Background(), call); err == nil {
			t.Fatalf("answer %s accepted", bad)
		}
	}
	if c, err := NewVerdictClient(JudgeConfig{}); c != nil || err != nil {
		t.Fatalf("empty URL: %v %v", c, err)
	}
	bad, _ := NewVerdictClient(JudgeConfig{URL: srv.URL + "/nope"})
	if _, err := bad.JudgeToolCall(context.Background(), call); err == nil {
		t.Fatal("HTTP error not reported")
	}
}
