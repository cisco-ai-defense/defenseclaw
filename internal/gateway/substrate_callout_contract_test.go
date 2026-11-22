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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

// TestSubstrateCalloutContractWithExtproc runs the egress callout's own
// verdict client against the gateway's admin listener (GAP-0015): same path,
// same request and answer, so a drift on either side fails here.
func TestSubstrateCalloutContractWithExtproc(t *testing.T) {
	f := newSubstrateFixture(t)
	srv := httptest.NewServer(f.admin)
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(subCallout+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := extproc.NewVerdictClient(extproc.JudgeConfig{URL: srv.URL + calloutapi.Path, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	call := extproc.ToolCall{
		Actor:  extproc.ActorRef{Atespace: "eng-web", Name: "alice-1"},
		Server: "docs", Host: "mcp.example.com", URL: "https://mcp.example.com/mcp", Tool: "search",
		Args: json.RawMessage(`{"q":"hello"}`), RequestID: "req-1", SessionID: "sess-1",
	}
	v, err := c.JudgeToolCall(context.Background(), call)
	if err != nil || v.Block || v.Ask {
		t.Fatalf("registered actor, benign call: %+v %v", v, err)
	}
	call.Actor.Name = "ghost"
	v, err = c.JudgeToolCall(context.Background(), call)
	if err != nil || !v.Block || v.Reason == "" {
		t.Fatalf("unregistered actor: %+v %v", v, err)
	}
	// A wrong token is an error the callout's failure mode handles, never
	// an allow.
	if err := os.WriteFile(tok, []byte("not-the-callout-token-000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.JudgeToolCall(context.Background(), call); err == nil {
		t.Fatal("wrong token answered without an error")
	}
}
