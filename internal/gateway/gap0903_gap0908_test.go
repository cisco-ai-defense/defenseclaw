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
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// hookSecrets runs hook once, inside the add's value write: after the add
// opened its ask and before it writes the binding (the RV4 F2 window).
type hookSecrets struct {
	*memSecrets
	hook func()
}

func (s *hookSecrets) Set(ctx context.Context, ns, name, key string, v []byte) error {
	if h := s.hook; h != nil {
		s.hook = nil
		h()
	}
	return s.memSecrets.Set(ctx, ns, name, key, v)
}

// GAP-0903: an administrator who answers a binding ask in the add window
// gets 200, and the add applies the answer to the binding it then writes.
func TestGAP0903AnswerInAddWindow(t *testing.T) {
	for decision, want := range map[string]string{"approve": "active", "deny": "denied"} {
		t.Run(decision, func(t *testing.T) {
			hs := &hookSecrets{memSecrets: &memSecrets{m: map[string][]byte{}}}
			bf := newBindingFixture(t, func(c *SubstrateConfig) { c.SecretStore = hs })
			decideCode := 0
			hs.hook = func() {
				list, _ := bf.asks.List(context.Background(), asks.ListRequest{All: true})
				for _, a := range list {
					if a.State == asks.StatePending {
						decideCode, _ = bf.decide(t, "p-admin", a.ID, decision)
					}
				}
			}
			code, out := bf.add(t, "p-alice", hardOutsideAdd)
			b := bf.binding(t, "alice", "gl-lab")
			if decideCode != http.StatusOK || string(b.State) != want {
				t.Errorf("%s in the add window: decide %d, add %d %v, binding %s; want 200 and %s", decision, decideCode, code, out, b.State, want)
			}
		})
	}
}

// rmRaceAsks runs after once, right after an approval wins its Resolve:
// an rm that lands between the answer and the binding write.
type rmRaceAsks struct {
	SubstrateAskStore
	after func()
}

func (s *rmRaceAsks) Resolve(ctx context.Context, in asks.ResolveRequest) (asks.Ask, error) {
	got, err := s.SubstrateAskStore.Resolve(ctx, in)
	if h := s.after; h != nil && in.Decision == "approve" {
		s.after = nil
		h()
	}
	return got, err
}

// GAP-0908: an approval that wins the race with rm stands, moves nothing
// (the binding is gone and stays gone) and writes its approval record.
func TestGAP0908ApproveRacingRmIsRecorded(t *testing.T) {
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	race := &rmRaceAsks{}
	bf := newBindingFixture(t, func(c *SubstrateConfig) { race.SubstrateAskStore = c.Asks; c.Asks = race })
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    compliance.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: relay-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n      send:\n        signals: [logs]\n        buckets: ['*']\n",
		fixture.dataDir, server.URL))
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.bindAPIServerObservabilityV8(bf.api)

	code, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("add: %d %v", code, out)
	}
	rmCode := 0
	race.after = func() {
		rmCode = bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-lab", "p-alice", "").Code
	}
	decideCode, dout := bf.decide(t, "p-admin", id, "approve")
	if rmCode != http.StatusOK {
		t.Fatalf("rm in the race: %d", rmCode)
	}
	if decideCode != http.StatusOK {
		t.Errorf("approve that won the race with rm: %d %v, want 200 (the answer stands and is recorded)", decideCode, dout)
	}
	if n := len(bf.store.ForOwner(render.PersonKey("alice"))); n != 0 {
		t.Errorf("rm then approve left %d bindings, want none", n)
	}

	db, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n := 0
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name = 'approval.resolved'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
	}
	if n == 0 {
		t.Errorf("no approval.resolved record for the approval that won the race with rm")
	}
}
