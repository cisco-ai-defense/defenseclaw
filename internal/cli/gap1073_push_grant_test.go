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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/substrate/pushgrant"
	"github.com/spf13/cobra"
)

// GAP-1073: the launcher asks for a grant (?grant=1), pushes under it and
// closes it after the push, also when the push fails; an older gateway (no
// grant) gets a warning and today's push; a close that saw no push to the
// approved repository is said.
func TestGAP1073PushRunsUnderTheGrant(t *testing.T) {
	const grant = "0123456789abcdef0123456789abcdef"
	var closes atomic.Int32
	pushes := `{"closed":true,"pushes":1}`
	var askedGrant atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actors/eng-web/alice-1/push"):
			askedGrant.Store(r.URL.Query().Get("grant") == "1")
			_, _ = w.Write([]byte(`{"decision":"allow","grant":"` + grant + `"}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/actors/eng-web/alice-1/push/"+grant):
			closes.Add(1)
			_, _ = w.Write([]byte(pushes))
		default:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	cl, err := api.New(api.Options{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := &substrateSession{Name: "test", Client: cl, Bearer: func(context.Context) (string, error) { return "t", nil }}
	a := api.Actor{Atespace: "eng-web", Name: "alice-1"}
	d, err := cl.PushIntent(ctx, a.Atespace, a.Name, api.PushRequest{Host: "git.example.test", Repo: "team/app", Branch: "agent/x", Head: strings.Repeat("a", 40)})
	if err != nil || d.Grant != grant || !askedGrant.Load() {
		t.Fatalf("intent: %+v %v (asked for a grant: %v)", d, err, askedGrant.Load())
	}
	run := func(d api.PushDecision, pushErr error) (string, bool, error) {
		var errw bytes.Buffer
		ran := false
		err := substratePushUnderGrant(ctx, &errw, s, a, d, "https://git.example.test/team/app.git", func() error { ran = true; return pushErr })
		return errw.String(), ran, err
	}
	if out, ran, err := run(d, nil); err != nil || !ran || out != "" || closes.Load() != 1 {
		t.Fatalf("granted push: %q ran=%v err=%v closes=%d", out, ran, err, closes.Load())
	}
	boom := errors.New("push failed")
	if _, _, err := run(d, boom); !errors.Is(err, boom) || closes.Load() != 2 {
		t.Fatalf("failed push: err=%v closes=%d, want the error and the grant closed", err, closes.Load())
	}
	pushes = `{"closed":true,"pushes":0}`
	if out, _, err := run(d, nil); err != nil || !strings.Contains(out, "egress saw no push") {
		t.Fatalf("unseen push: %q %v", out, err)
	}
	pushes = `{"closed":false,"pushes":0}`
	if out, _, _ := run(d, nil); !strings.Contains(out, "lost the egress grant") {
		t.Fatalf("lost grant: %q", out)
	}
	if out, ran, err := run(api.PushDecision{Decision: "allow"}, nil); err != nil || !ran || !strings.Contains(out, "gateway is older") {
		t.Fatalf("older gateway: %q ran=%v err=%v, want a warning and the push", out, ran, err)
	}
	if out, ran, _ := run(api.PushDecision{Decision: "allow", GrantError: "push_grants_unavailable"}, nil); !ran || !strings.Contains(out, "could not open the egress grant") {
		t.Fatalf("grant error: %q ran=%v", out, ran)
	}
}

// GAP-1073: the callout may check a push against the grants, never open or
// close one; gateways do all three.
func TestGAP1073LeaderPushGrantPermissions(t *testing.T) {
	p := substrateLeaderPermissions([]string{"spiffe://c/gw"}, []string{"spiffe://c/co"}, []string{"spiffe://c/ctl"})
	for _, m := range pushgrant.Methods {
		if !p.Allows("spiffe://c/gw", m) {
			t.Errorf("gateway must call %s", m)
		}
		if p.Allows("spiffe://c/co", m) != (m == pushgrant.MethodCheck) {
			t.Errorf("callout and %s: %v", m, p.Allows("spiffe://c/co", m))
		}
		if p.Allows("spiffe://c/ctl", m) || p.Allows("spiffe://c/other", m) {
			t.Errorf("controller or stranger may call %s", m)
		}
	}
}

// GAP-1073 (RV-REG nit a): every grant the ask poll opens is closed. The
// gateway opens a grant only with an allow, the poll ends at the first
// allow, and the push closes that grant: polls that answered ask opened
// none, and nothing is asked again after the allow.
func TestGAP1073AskPollClosesEveryGrantItOpened(t *testing.T) {
	old := substratePushPoll
	substratePushPoll = time.Millisecond
	t.Cleanup(func() { substratePushPoll = old })
	var posts atomic.Int32
	opened := map[string]bool{}
	closed := map[string]int{}
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actors/eng-web/alice-1/push"):
			if n := posts.Add(1); n < 3 {
				_, _ = w.Write([]byte(`{"decision":"ask","ask_id":"ask-1","summary":"Push agent/x?"}`))
				return
			}
			id := fmt.Sprintf("%032x", posts.Load())
			opened[id] = true
			_, _ = w.Write([]byte(`{"decision":"allow","grant":"` + id + `"}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/actors/eng-web/alice-1/push/"):
			closed[r.URL.Path[strings.LastIndexByte(r.URL.Path, 0x2f)+1:]]++
			_, _ = w.Write([]byte(`{"closed":true,"pushes":1}`))
		default:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	cl, err := api.New(api.Options{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := &substrateSession{Name: "test", Client: cl, Bearer: func(context.Context) (string, error) { return "t", nil }}
	a := api.Actor{Atespace: "eng-web", Name: "alice-1"}
	cmd := &cobra.Command{}
	var errw bytes.Buffer
	cmd.SetIn(strings.NewReader(""))
	cmd.SetErr(&errw)
	d, err := substratePushDecide(ctx, cmd, &substratePullFlags{}, s, a, api.PushRequest{Host: "git.example.test", Repo: "team/app", Branch: "agent/x", Head: strings.Repeat("a", 40)})
	if err != nil {
		t.Fatalf("decide: %v (%s)", err, errw.String())
	}
	if err := substratePushUnderGrant(ctx, &errw, s, a, d, "https://git.example.test/team/app.git", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts.Load() != 3 || len(opened) != 1 {
		t.Fatalf("the poll asked %d times and opened %d grants, want 3 asks and 1 grant", posts.Load(), len(opened))
	}
	for id := range opened {
		if closed[id] != 1 {
			t.Errorf("grant %s closed %d times, want once", id, closed[id])
		}
	}
	if len(closed) != len(opened) {
		t.Errorf("closed %v, opened %v", closed, opened)
	}
}
