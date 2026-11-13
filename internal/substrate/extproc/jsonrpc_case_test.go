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
	"testing"
)

// TestJSONRPCKeyCaseGAP0156: keys match without case, as a Go-decoded MCP
// server reads them, and two keys that differ only in case are refused as
// ambiguous, in closed and open mode alike.
func TestJSONRPCKeyCaseGAP0156(t *testing.T) {
	cases := []struct {
		name, body string
		// judged is the tool the judge must see ("" = not judged); refused
		// means an ambiguity refusal.
		judged  string
		refused bool
	}{
		{"Method", `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"drop_tables"}}`, "drop_tables", false},
		{"METHOD", `{"jsonrpc":"2.0","id":1,"METHOD":"tools/call","params":{"name":"drop_tables"}}`, "drop_tables", false},
		{"Params and Name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Params":{"NAME":"drop_tables"}}`, "drop_tables", false},
		{"long s in params", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"paramſ\":{\"name\":\"drop_tables\"}}", "drop_tables", false},
		{"method and METHOD", `{"jsonrpc":"2.0","id":1,"method":"ping","METHOD":"tools/call","params":{"name":"drop_tables"}}`, "", true},
		{"name and Name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list","Name":"drop_tables"}}`, "", true},
		{"params and PARAMS", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list"},"PARAMS":{"name":"drop_tables"}}`, "", true},
		{"arguments and Arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{},"Arguments":{"q":1}}}`, "", true},
		{"lower case stays", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list"}}`, "list", false},
		{"other method", `{"jsonrpc":"2.0","id":1,"Method":"tools/list"}`, "", false},
	}
	for _, mode := range []string{FailureClosed, FailureOpen} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				if !json.Valid([]byte(c.body)) {
					t.Fatalf("test body is not JSON: %s", c.body)
				}
				h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = mode })
				r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
				v := h.eng.DecideBody(context.Background(), r, Verdict{Allow: true}, []byte(c.body))
				if c.refused {
					if v.Allow || v.Category != CategoryMCPToolBlocked || v.Rule != "jsonrpc" || len(h.judge.calls) != 0 {
						t.Fatalf("not refused as ambiguous: %+v", v)
					}
					return
				}
				if !v.Allow {
					t.Fatalf("refused: %+v", v)
				}
				switch {
				case c.judged == "" && len(h.judge.calls) != 0:
					t.Fatalf("judged %+v", h.judge.calls)
				case c.judged != "" && (len(h.judge.calls) != 1 || h.judge.calls[0].Tool != c.judged):
					t.Fatalf("judge saw %+v, want %s", h.judge.calls, c.judged)
				}
			})
		}
	}
}
