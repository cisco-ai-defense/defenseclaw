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

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
)

// TestSubstrateAsksPendingFindsTheAttachedAgentsAskGAP0483: the gateway
// lists an ask with its atespace and the actor's bare name apart (askView
// in internal/gateway/substrate_asks.go), and the attached launcher shows
// it on its row as atespace/name. Before the fix the launcher compared the
// bare name with atespace/name, so no ask ever reached the pane and
// Ctrl-\ did nothing; the ask was only in `substrate approvals`. An ask of
// the same name in another atespace, of another agent, or with no
// atespace is still never shown (GAP-0112).
func TestSubstrateAsksPendingFindsTheAttachedAgentsAskGAP0483(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/substrate/asks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"asks":[
			{"id":"ask-1","atespace":"dc-eng","actor":"claude-b66c97d1","kind":"egress","host":"example.com","summary":"GET example.com","state":"pending","created":"2026-11-17T18:49:56Z"},
			{"id":"ask-2","atespace":"dc-other","actor":"claude-b66c97d1","kind":"egress","host":"example.com","summary":"GET example.com","state":"pending"},
			{"id":"ask-3","atespace":"dc-eng","actor":"codex-0a1b2c3d","kind":"egress","host":"example.com","summary":"GET example.com","state":"pending"},
			{"id":"ask-4","actor":"claude-b66c97d1","kind":"egress","host":"example.com","summary":"GET example.com","state":"pending"}]}`)
	}))
	defer srv.Close()
	cl, err := api.New(api.Options{Base: srv.URL, Token: func(context.Context) (string, error) { return "tok", nil }})
	if err != nil {
		t.Fatal(err)
	}
	target := attach.Target{Atespace: "dc-eng", Name: "claude-b66c97d1"}
	got, err := substrateAsks{cl}.Pending(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ask-1" || got[0].Actor != target.String() || got[0].Summary != "GET example.com" {
		t.Fatalf("the attached agent's asks: %+v (want only ask-1, actor %s)", got, target)
	}
}
