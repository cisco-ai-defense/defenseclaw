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

package controller_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// calloutLeader is a leader serving the callout methods, and a client.
func calloutLeader(t *testing.T, board *controller.CalloutBoard) *leader.Client {
	t.Helper()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	controller.ServeCallout(srv, board)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}
}

const oursEnvoy = `static_resources:
  clusters:
  - name: additional_egress_ext_proc
    load_assignment:
      cluster_name: additional_egress_ext_proc
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: defenseclaw-callout.dc.svc.cluster.local
                port_value: 9443
`

// GAP-0505 (lead ruling on the RBAC exception): when the controller's get
// of atenet-egress is forbidden, the slot is unknown: one WARN that says it
// cannot verify the egress callout, and never "ours". At e1f0863e6c a 403
// after a good read kept reporting the last state (the DefenseClaw
// callout). This runs the shipped Kubernetes client against an API server
// that answers 403, and the gateway's view through the leader.
func TestCalloutForbiddenGetIsUnknownGAP0505(t *testing.T) {
	var forbidden atomic.Bool
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/ate-system/configmaps/atenet-egress" || r.Method != http.MethodGet {
			http.Error(w, `{"message":"unexpected request"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if forbidden.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"configmaps \"atenet-egress\" is forbidden: User \"system:serviceaccount:dc:defenseclaw-controller\" cannot get resource \"configmaps\" in the namespace \"ate-system\"","code":403}`))
			return
		}
		raw, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "atenet-egress", "namespace": "ate-system"},
			"data": map[string]string{setup.EgressEnvoyKey: oursEnvoy}})
		_, _ = w.Write(raw)
	}))
	defer api.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	kube, err := setup.NewKube(api.URL, token, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, nil)
	r.ctl.SetCallout(&setup.EgressCalloutReader{Kube: kube, SubstrateNamespace: "ate-system", Namespace: "dc"})
	cl := calloutLeader(t, &controller.CalloutBoard{})
	r.ctl.SetCalloutPublisher(&controller.LeaderCalloutPublisher{Leader: cl})
	gw := &controller.LeaderCallout{Leader: cl}
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	ctx := context.Background()

	r.pass()
	if st, ok := r.ctl.CalloutStatus(ctx); !ok || !st.Known || !st.Ours || st.Holder != "dc/defenseclaw-callout:9443" {
		t.Fatalf("readable: status = %+v, %v", st, ok)
	}
	if slot, err := gw.ReadCalloutSlot(ctx); err != nil || !slot.Ours {
		t.Fatalf("gateway view, readable: %+v, %v", slot, err)
	}

	forbidden.Store(true)
	r.next()
	r.next()
	st, ok := r.ctl.CalloutStatus(ctx)
	if !ok || st.Known || st.Ours || st.Holder != "" || !strings.Contains(st.Err, "403") {
		t.Fatalf("forbidden: status = %+v, %v (must be unknown, never ours)", st, ok)
	}
	var warns []controller.Event
	for _, w := range r.sink.Events(controller.EventWarning) {
		if strings.Contains(w.Message, "cannot verify the egress callout") {
			warns = append(warns, w)
		}
	}
	if len(warns) != 1 || warns[0].Severity != controller.SeverityWarn || !strings.Contains(warns[0].Message, "403") {
		t.Fatalf("forbidden: WARN events = %+v", warns)
	}
	// The gateway sees unknown too, never the DefenseClaw callout.
	if slot, err := gw.ReadCalloutSlot(ctx); err == nil || slot.Ours || !strings.Contains(err.Error(), "403") {
		t.Fatalf("gateway view, forbidden: %+v, %v", slot, err)
	}
	// Policies: a slot read as the DefenseClaw callout and now unknown
	// changes nothing (no deny-only from a read that failed).
	if !render.Equal(r.api.Policy(ref), r.want(ref)) {
		t.Fatal("a forbidden read changed the policy")
	}
}

// The leader round trip: the controller publishes each read, the gateway's
// reader gets it, and the board never stores an unread slot as anyone's.
func TestCalloutLeaderRoundTripGAP0505(t *testing.T) {
	ctx := context.Background()
	board := &controller.CalloutBoard{}
	cl := calloutLeader(t, board)
	r := newRig(t, nil)
	slots := &slotReader{slot: otherSlot}
	r.ctl.SetCallout(slots)
	r.ctl.SetCalloutPublisher(&controller.LeaderCalloutPublisher{Leader: cl})
	r.pass()
	var ans controller.CalloutAnswer
	if err := cl.Call(ctx, leader.MethodCalloutStatus, leader.NewRequestID(), struct{}{}, &ans); err != nil {
		t.Fatal(err)
	}
	p := ans.Published
	if p == nil || !p.Known || p.Ours || p.Holder != otherSlot.Holder || p.FailMode != controller.CalloutFailClosed || !p.ReadAt.Equal(r.clk.Now()) {
		t.Fatalf("published = %+v", p)
	}
	gw := &controller.LeaderCallout{Leader: cl}
	if slot, err := gw.ReadCalloutSlot(ctx); err != nil || slot.Ours || slot.Holder != otherSlot.Holder {
		t.Fatalf("gateway view: %+v, %v", slot, err)
	}
	slots.set(ourSlot, nil)
	r.next()
	if slot, err := gw.ReadCalloutSlot(ctx); err != nil || !slot.Ours {
		t.Fatalf("gateway view after the DefenseClaw callout is back: %+v, %v", slot, err)
	}
	// Within the read interval no publish: one per read, not one per pass.
	before := slots.reads
	r.pass()
	r.pass()
	if slots.reads != before {
		t.Fatalf("%d reads inside the interval", slots.reads-before)
	}

	// An unknown slot is stored as neither ours nor anyone's; a late
	// retry of an older read does not replace a newer one.
	later := r.clk.Now().Add(time.Minute)
	if _, err := board.Publish(ctx, controller.PublishedCallout{Known: false, Ours: true, Holder: ourSlot.Holder, Err: "forbidden", ReadAt: later}); err != nil {
		t.Fatal(err)
	}
	if _, err := board.Publish(ctx, controller.PublishedCallout{Known: true, Ours: true, Holder: ourSlot.Holder, ReadAt: later.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	got, _ := board.Status(ctx, struct{}{})
	if got.Published == nil || got.Published.Known || got.Published.Ours || got.Published.Holder != "" {
		t.Fatalf("board = %+v", got.Published)
	}
	if slot, err := gw.ReadCalloutSlot(ctx); err == nil || slot.Ours || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("gateway view of an unknown report: %+v, %v", slot, err)
	}
}

// A report older than three read intervals, or none at all, is unknown at
// the gateway: /info and doctor say they cannot verify the egress callout,
// never the DefenseClaw callout.
func TestCalloutStaleReportIsUnknownGAP0505(t *testing.T) {
	ctx := context.Background()
	bclk := &clock{t: time.Date(2026, 11, 17, 21, 0, 0, 0, time.UTC)}
	board := &controller.CalloutBoard{Now: bclk.Now}
	cl := calloutLeader(t, board)
	gw := &controller.LeaderCallout{Leader: cl}
	if _, err := gw.ReadCalloutSlot(ctx); err == nil || !strings.Contains(err.Error(), "has not reported") {
		t.Fatalf("no report: %v", err)
	}
	pub := &controller.LeaderCalloutPublisher{Leader: cl}
	if err := pub.PublishCallout(ctx, controller.CalloutStatus{Known: true, Ours: true, Holder: ourSlot.Holder, FailMode: controller.CalloutFailClosed,
		At: bclk.Now()}); err != nil {
		t.Fatal(err)
	}
	if slot, err := gw.ReadCalloutSlot(ctx); err != nil || !slot.Ours {
		t.Fatalf("fresh: %+v, %v", slot, err)
	}
	bclk.Add(controller.CalloutStaleAfter - time.Second)
	if _, err := gw.ReadCalloutSlot(ctx); err != nil {
		t.Fatalf("not yet stale: %v", err)
	}
	bclk.Add(2 * time.Second)
	if slot, err := gw.ReadCalloutSlot(ctx); err == nil || slot.Ours || !strings.Contains(err.Error(), "old") {
		t.Fatalf("stale: %+v, %v", slot, err)
	}
	// The gateway's controller (the create path and /info) reports it as
	// unknown.
	g := newRig(t, nil)
	g.ctl.SetCallout(gw)
	st, ok := g.ctl.CalloutStatus(ctx)
	if !ok || st.Known || st.Ours || st.Holder != "" || !strings.Contains(st.Err, "old") {
		t.Fatalf("gateway status of a stale report = %+v, %v", st, ok)
	}
}

// The gateway's create path follows the controller's published read: other
// or none in closed mode gives deny-only; ours or unknown keeps the full
// policy (the unknown behaviour of a slot never read).
func TestCalloutCreatePathFollowsPublishedReadGAP0505(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		st       controller.CalloutStatus
		denyOnly bool
	}{
		{"other", controller.CalloutStatus{Known: true, Holder: otherSlot.Holder}, true},
		{"none", controller.CalloutStatus{Known: true}, true},
		{"ours", controller.CalloutStatus{Known: true, Ours: true, Holder: ourSlot.Holder}, false},
		{"unknown", controller.CalloutStatus{Err: "kubernetes API 403: forbidden"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := calloutLeader(t, &controller.CalloutBoard{})
			tc.st.FailMode, tc.st.At = controller.CalloutFailClosed, time.Now()
			if err := (&controller.LeaderCalloutPublisher{Leader: cl}).PublishCallout(ctx, tc.st); err != nil {
				t.Fatal(err)
			}
			g := newRig(t, nil)
			g.ctl.SetCallout(&controller.LeaderCallout{Leader: cl})
			a := g.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
			ref := ateapi.RefOf(a.GetMetadata())
			if err := g.ctl.EnsurePolicy(ctx, ref); err != nil {
				t.Fatal(err)
			}
			want := g.want(ref)
			if tc.denyOnly {
				want = g.denyOnly()
			}
			if !render.Equal(g.api.Policy(ref), want) {
				t.Fatalf("create path with a published %s read: policy = %v", tc.name, g.api.Policy(ref).GetRules())
			}
		})
	}
}
