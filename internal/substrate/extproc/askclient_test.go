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
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
)

// The callout's asks reach the gateway's callout ask route (A2's AskSink):
// the URL comes from judge.url, the token and client tag go along, a held
// request reads its ask again by id, and each gateway state maps to an
// outcome.
func TestAskClientAgainstTheCalloutAskRoute(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	answers := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != AskPath || r.Header.Get("Authorization") != "Bearer tok-callout" || r.Header.Get("X-DefenseClaw-Client") != calloutapi.ClientTag {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		bodies = append(bodies, in)
		host, _ := in["host"].(string)
		q := answers[host]
		a := q[0]
		if len(q) > 1 {
			answers[host] = q[1:]
		}
		mu.Unlock()
		_, _ = w.Write([]byte(a))
	}))
	defer srv.Close()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("tok-callout\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewAskClient(&Config{Judge: JudgeConfig{URL: srv.URL + calloutapi.Path, TokenFile: tok}})
	if err != nil || c == nil {
		t.Fatalf("client %v %v", c, err)
	}
	c.poll = 5 * time.Millisecond
	answers["deny.example.org"] = []string{`{"state":"denied","reason":"unattended runs do not ask"}`}
	answers["ok.example.org"] = []string{`{"id":"ask-1","state":"pending"}`, `{"id":"ask-1","state":"pending"}`, `{"id":"ask-1","state":"approved"}`}
	answers["no.example.org"] = []string{`{"id":"ask-2","state":"pending"}`, `{"id":"ask-2","state":"denied","note":"not this week"}`}
	answers["wait.example.org"] = []string{`{"id":"ask-3","state":"pending","unattended":true}`}
	req := func(host string) AskRequest {
		return AskRequest{Actor: ActorRef{Atespace: "eng-web", Name: "nightly-1", UID: "u1"}, Host: host, Method: "GET", Rule: "ask_hosts:*.example.org"}
	}
	ctx := context.Background()
	if res, err := c.Ask(ctx, req("deny.example.org")); err != nil || res.Outcome != AskDenied || res.Reason != "unattended runs do not ask" {
		t.Fatalf("unattended deny: %+v %v", res, err)
	}
	if res, err := c.Ask(ctx, req("ok.example.org")); err != nil || res.Outcome != AskApproved || res.ID != "ask-1" {
		t.Fatalf("approved: %+v %v", res, err)
	}
	if res, err := c.Ask(ctx, req("no.example.org")); err != nil || res.Outcome != AskDenied || res.Reason != "not this week" {
		t.Fatalf("denied by a person: %+v %v", res, err)
	}
	hold, cancel := context.WithTimeout(ctx, 60*time.Millisecond)
	defer cancel()
	if res, err := c.Ask(hold, req("wait.example.org")); err != nil || res.Outcome != AskPending || res.ID != "ask-3" {
		t.Fatalf("hold ends while pending: %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	first, later := bodies[1], bodies[2]
	if first["ask_id"] != nil || later["ask_id"] != "ask-1" {
		t.Fatalf("a held request reads its ask by id: %v then %v", first, later)
	}
	if a, _ := first["actor"].(map[string]any); a["atespace"] != "eng-web" || a["name"] != "nightly-1" || a["uid"] != "u1" {
		t.Fatalf("actor %v", first["actor"])
	}
	for _, b := range bodies {
		for k := range b {
			if k != "actor" && k != "host" && k != "summary" && k != "reason" && k != "rule" && k != "ask_id" {
				t.Fatalf("unexpected field %q sent to the gateway", k)
			}
		}
	}
}

func TestAskClientNeedsAGatewayURL(t *testing.T) {
	if c, err := NewAskClient(&Config{}); c != nil || err != nil {
		t.Fatalf("no judge, no ask url: %v %v", c, err)
	}
	if c, err := NewAskClient(&Config{Judge: JudgeConfig{URL: "https://gw.example/other"}}); c != nil || err != nil {
		t.Fatalf("a judge url that is not the verdict route: %v %v", c, err)
	}
	c, err := NewAskClient(&Config{Judge: JudgeConfig{URL: "https://gw.example:8443" + calloutapi.Path}})
	if err != nil || c == nil || c.url != "https://gw.example:8443/api/v1/substrate/callout/ask" {
		t.Fatalf("ask url from judge.url: %v %v", c, err)
	}
}

// GAP-0177: the gateway gets the rule (it keys the approval) and the person
// sees the path prefix a url rule approval covers.
func TestAskClientSendsTheRuleAndPathPrefix(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"state":"denied","reason":"unattended runs do not ask"}`))
	}))
	defer srv.Close()
	c, err := NewAskClient(&Config{Judge: JudgeConfig{URL: srv.URL + calloutapi.Path}})
	if err != nil || c == nil {
		t.Fatal(c, err)
	}
	_, _ = c.Ask(context.Background(), AskRequest{Actor: ActorRef{Atespace: "a", Name: "n"}, Host: "api.github.com", Method: "DELETE",
		Rule: "url_rules:admin-delete-ask", PathPrefix: "/admin"})
	if got["rule"] != "url_rules:admin-delete-ask" || got["summary"] != "DELETE api.github.com /admin*" {
		t.Fatalf("wire %v", got)
	}
}
