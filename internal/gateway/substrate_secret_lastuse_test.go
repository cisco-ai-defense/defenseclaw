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
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

type fakeSecretUses struct {
	uses  []telemetryrelay.HostUse
	err   error
	asked []telemetryrelay.ActorRef
}

func (f *fakeSecretUses) HostUses(_ context.Context, actors []telemetryrelay.ActorRef) ([]telemetryrelay.HostUse, error) {
	f.asked = actors
	return f.uses, f.err
}

// S6b: secrets list and test show the newest request by one of the
// caller's own agents to a host the secret is added on: when, the host
// and the agent. Another person's agent, a host the secret is not bound
// to, and a use before an own binding was added never count; a reader
// that fails leaves the last use out and the list still answers.
func TestB1SecretLastUseS6b(t *testing.T) {
	fu := &fakeSecretUses{}
	bf := newBindingFixture(t, func(c *SubstrateConfig) { c.SecretUses = fu })
	bf.values.m["dc-secrets/github/token"] = []byte("x")
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	created := bf.binding(t, "alice", "gl-work").Created
	at := func(d time.Duration) time.Time { return time.Now().Add(d).UTC().Truncate(time.Second) }
	fu.uses = []telemetryrelay.HostUse{ // newest first, as the leader answers
		{Atespace: "eng-web", UID: subUID1, Host: "evil.example", At: at(0)},
		{Atespace: "eng-web", UID: subUID2, Host: "gitlab.com", At: at(-time.Minute)}, // bob's agent
		{Atespace: "eng-web", UID: subUID1, Host: "github.com", At: at(-time.Hour)},
		{Atespace: "eng-web", UID: subUID1, Host: "gitlab.com", At: created.Add(-time.Hour)}, // before the binding
	}
	list := func() map[string]map[string]any {
		t.Helper()
		rec := bf.do(t, bf.admin, http.MethodGet, "/api/v1/substrate/secrets", "p-alice", "")
		var out struct {
			Secrets []map[string]any `json:"secrets"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		got := map[string]map[string]any{}
		for _, s := range out.Secrets {
			got[s["name"].(string)] = s
		}
		return got
	}
	got := list()
	if gh := got["github-push"]; gh["last_used"] != at(-time.Hour).Format(time.RFC3339) || gh["last_used_host"] != "github.com" || gh["last_used_agent"] != "alice-1" {
		t.Errorf("github-push: %v", gh)
	}
	if gl := got["gl-work"]; gl["last_used"] != nil {
		t.Errorf("gl-work counts another person's use or one before it was added: %v", gl)
	}
	for _, a := range fu.asked {
		if a.UID != subUID1 {
			t.Errorf("asked for another person's agent: %v", fu.asked)
		}
	}

	used := created.Add(time.Second).UTC()
	fu.uses = append([]telemetryrelay.HostUse{{Atespace: "eng-web", UID: subUID1, Host: "gitlab.com", At: used}}, fu.uses...)
	if gl := list()["gl-work"]; gl["last_used"] != used.Format(time.RFC3339Nano) || gl["last_used_host"] != "gitlab.com" || gl["last_used_agent"] != "alice-1" {
		t.Errorf("gl-work: %v", gl)
	}
	rec := bf.do(t, bf.admin, http.MethodPost, "/api/v1/substrate/secrets/gl-work/test", "p-alice", "")
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out["last_used_host"] != "gitlab.com" || out["last_used_agent"] != "alice-1" {
		t.Errorf("test gl-work: %d %v", rec.Code, out)
	}

	fu.err = errors.New("leader down")
	if gh := list()["github-push"]; gh == nil || gh["last_used"] != nil {
		t.Errorf("reader error: %v", gh)
	}
}

func TestSubstrateHostCovered(t *testing.T) {
	for _, c := range []struct {
		pats []string
		host string
		want bool
	}{
		{[]string{"github.com"}, "github.com", true},
		{[]string{"GitHub.com."}, "github.com", true},
		{[]string{"*.corp.example"}, "git.corp.example", true},
		{[]string{"*.corp.example"}, "corp.example", false},
		{[]string{"*.corp.example"}, "evilcorp.example", false},
		{[]string{"github.com"}, "api.github.com", false},
		{nil, "github.com", false},
	} {
		if got := substrateHostCovered(c.pats, c.host); got != c.want {
			t.Errorf("substrateHostCovered(%v, %q) = %v", c.pats, c.host, got)
		}
	}
}
