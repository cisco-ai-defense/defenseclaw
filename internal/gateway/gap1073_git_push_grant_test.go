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

// newSubstrateFixture is unix-only (substrate_listener_test.go).
//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/pushgrant"
)

type fakePushGrants struct {
	s      *pushgrant.Store
	opened []pushgrant.OpenRequest
	fail   bool
}

func (f *fakePushGrants) OpenPushGrant(ctx context.Context, in pushgrant.OpenRequest) (pushgrant.Opened, error) {
	if f.fail {
		return pushgrant.Opened{}, errors.New("leader: unknown_method")
	}
	f.opened = append(f.opened, in)
	return f.s.Open(ctx, in)
}

func (f *fakePushGrants) ClosePushGrant(ctx context.Context, in pushgrant.CloseRequest) (pushgrant.Closed, error) {
	return f.s.Close(ctx, in)
}

// GAP-1073: an allowed pull --push-branch that asks for a grant (?grant=1)
// gets one for the actor, host and repository it was allowed; only the
// actor's person closes it; a launcher that does not ask (an older CLI)
// opens none; a grant that cannot be opened is said, never a refusal.
func TestGAP1073GitPushOpensAndClosesTheGrant(t *testing.T) {
	grants := &fakePushGrants{s: pushgrant.NewStore()}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks = asks.NewMemory()
		c.GitPush = func(string) string { return config.SubstrateGitPushAllow }
		c.PushGrants = grants
	})
	b, _ := json.Marshal(map[string]any{"host": "git.example.test", "repo": "team/app", "branch": "agent/x",
		"head": strings.Repeat("a", 40), "commits": 1, "files": 1})
	push := func(q string) map[string]any {
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/push"+q, "p-alice", string(b))
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if rec.Code != http.StatusOK || v["decision"] != "allow" {
			t.Fatalf("push%s: %d %v", q, rec.Code, v)
		}
		return v
	}
	if v := push(""); v["grant"] != nil || len(grants.opened) != 0 {
		t.Fatalf("no ?grant=1 opened a grant: %v", v)
	}
	v := push("?grant=1")
	id, _ := v["grant"].(string)
	if !pushgrant.ValidID(id) || len(grants.opened) != 1 {
		t.Fatalf("allow with ?grant=1: %v", v)
	}
	if o := grants.opened[0]; o.Atespace != "eng-web" || o.Actor != "alice-1" || o.Host != "git.example.test" || o.Repo != "team/app" || o.Ref != "refs/heads/agent/x" {
		t.Fatalf("grant opened for %+v", o)
	}
	del := func(person, gid string) (int, map[string]any) {
		rec := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/actors/eng-web/alice-1/push/"+gid, person, "")
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	if code, _ := del("p-bob", id); code == http.StatusOK {
		t.Fatal("bob closed alice's grant")
	}
	if code, _ := del("p-alice", "not-an-id"); code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", code)
	}
	if code, v := del("p-alice", id); code != http.StatusOK || v["closed"] != true {
		t.Fatalf("close: %d %v", code, v)
	}
	if _, v := del("p-alice", id); v["closed"] != false {
		t.Fatalf("second close: %v", v)
	}
	grants.fail = true
	if v := push("?grant=1"); v["grant"] != nil || v["grant_error"] == nil {
		t.Fatalf("failed open: %v, want an allow that names the grant error", v)
	}
}
