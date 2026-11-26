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

package pushgrant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func open(t *testing.T, s *Store, actor, repo string) Opened {
	t.Helper()
	g, err := s.Open(context.Background(), OpenRequest{Atespace: "eng", Actor: actor, Host: "Git.Example.Test:443", Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(g.ID) {
		t.Fatalf("id %q", g.ID)
	}
	return g
}

// GAP-1073: open, check, close, expiry, bounds and who may close.
func TestGAP1073GrantStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s := NewStore()
	s.Now = func() time.Time { return now }
	if a, _ := s.Check(ctx, CheckRequest{Atespace: "eng", Actor: "a1", Host: "git.example.test", Repo: "team/x"}); a.Active {
		t.Fatal("no grant must be inactive")
	}
	g := open(t, s, "a1", "/team/app.git")
	for _, c := range []struct {
		host, repo string
		match      bool
	}{
		{"git.example.test", "/team/app.git", true}, {"GIT.example.test.", "team/APP", true},
		{"git.example.test", "team/app/", true}, {"git.example.test", "team/other", false},
		{"git2.example.test", "team/app", false}, {"git.example.test", "", false},
	} {
		a, _ := s.Check(ctx, CheckRequest{Atespace: "eng", Actor: "a1", Host: c.host, Repo: c.repo, Push: true})
		if !a.Active || a.Match != c.match || a.Granted != "git.example.test/team/app" {
			t.Errorf("%s %s: %+v, want match=%v", c.host, c.repo, a, c.match)
		}
	}
	if a, _ := s.Check(ctx, CheckRequest{Atespace: "eng2", Actor: "a1", Host: "git.example.test", Repo: "team/other"}); a.Active {
		t.Fatal("a same-name actor of another atespace holds no grant")
	}
	if c, _ := s.Close(ctx, CloseRequest{Atespace: "eng", Actor: "a2", ID: g.ID}); c.Found {
		t.Fatal("another actor closed the grant")
	}
	if c, _ := s.Close(ctx, CloseRequest{Atespace: "eng", Actor: "a1", ID: g.ID}); !c.Found || c.Pushes != 3 {
		t.Fatalf("close: %+v, want the 3 matching pushes", c)
	}
	if c, _ := s.Close(ctx, CloseRequest{Atespace: "eng", Actor: "a1", ID: g.ID}); c.Found {
		t.Fatal("closed twice")
	}
	g = open(t, s, "a1", "team/app")
	now = now.Add(TTL)
	if a, _ := s.Check(ctx, CheckRequest{Atespace: "eng", Actor: "a1", Host: "git.example.test", Repo: "team/other"}); a.Active {
		t.Fatal("an expired grant still holds")
	}
	if c, _ := s.Close(ctx, CloseRequest{Atespace: "eng", Actor: "a1", ID: g.ID}); c.Found {
		t.Fatal("an expired grant closed as found")
	}
	var first Opened
	for i := 0; i < MaxPerActor+1; i++ {
		now = now.Add(time.Second)
		if g := open(t, s, "a1", "team/r"+strconv.Itoa(i)); i == 0 {
			first = g
		}
	}
	if c, _ := s.Close(ctx, CloseRequest{Atespace: "eng", Actor: "a1", ID: first.ID}); c.Found {
		t.Fatal("the oldest grant of a full actor must leave first")
	}
	for i := len(s.grants); i < MaxGrants; i++ {
		open(t, s, "b"+strconv.Itoa(i), "team/app")
	}
	if _, err := s.Open(ctx, OpenRequest{Atespace: "eng", Actor: "z", Host: "h", Repo: "r"}); err == nil {
		t.Fatal("a full store must refuse")
	}
	for _, bad := range []OpenRequest{{Actor: "a", Host: "h", Repo: "r"}, {Atespace: "e", Host: "h", Repo: "r"},
		{Atespace: "e", Actor: "a", Repo: "r"}, {Atespace: "e", Actor: "a", Host: "h", Repo: "/.git"}} {
		if _, err := NewStore().Open(ctx, bad); err == nil {
			t.Errorf("open %+v: want a refusal", bad)
		}
	}
}

// GAP-1073: an older leader (unknown_method) holds no grants, so the
// callout decides the push as before; any other failure is an outage.
func TestGAP1073ClientOlderLeader(t *testing.T) {
	code := leader.CodeUnknownMethod
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(leader.Response{Error: &leader.WireError{Code: code, Message: "unknown method"}})
	}))
	defer srv.Close()
	c := &Client{Leader: &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Millisecond}}
	active, match, _, err := c.CheckPush(context.Background(), "eng", "a1", "h", "r", true)
	if err != nil || active || match {
		t.Fatalf("older leader: active=%v match=%v err=%v", active, match, err)
	}
	code = leader.CodeInternal
	if _, _, _, err := c.CheckPush(context.Background(), "eng", "a1", "h", "r", true); err == nil {
		t.Fatal("a failed check must be an error")
	}
	if _, _, _, err := (&Client{}).CheckPush(context.Background(), "eng", "a1", "h", "r", true); err == nil {
		t.Fatal("no leader client must be an error")
	}
}
