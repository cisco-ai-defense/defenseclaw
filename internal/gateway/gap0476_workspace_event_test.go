//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0476: the digest the launcher sends for a file it reverted is the one
// the chain projector gives the same path in a Linux agent.
func TestGAP0476LauncherDigestIsTheProjectorsPathDigest(t *testing.T) {
	for _, p := range []string{"/work/app/dl.sh", "/work/app/sub/../x.bin"} {
		want, ok := exactArtifactIntentPathDigest(actionfacts.PathFact{Value: p, Resolved: strings.ReplaceAll(p, "sub/../", ""), Flavor: actionfacts.PathFlavorPOSIX})
		got, gok := guardrail.ToolChainPOSIXPathDigest(p)
		if !ok || !gok || got != want {
			t.Fatalf("%s: launcher %s, projector %s", p, got, want)
		}
	}
	if _, ok := guardrail.ToolChainPOSIXPathDigest("work/app/dl.sh"); ok {
		t.Fatal("a relative path has a digest")
	}
}

// GAP-0476: the owner's launcher reports a checkpoint and an undo through
// the gateway to the leader's chain state; someone else cannot, a bad body
// is refused, and a leader that refuses the event is a 502.
func TestGAP0476WorkspaceEventRoute(t *testing.T) {
	svc, err := chainstate.New(chainstate.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	srv := httptest.NewServer(ls)
	t.Cleanup(func() { srv.Close(); _ = svc.Close() })
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Chains = &chainstate.Client{Leader: &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Second}}
	})
	const path = "/api/v1/substrate/actors/eng-web/alice-1/workspace-event"
	commit := strings.Repeat("ab", 20)
	digest, _ := guardrail.ToolChainPOSIXPathDigest("/work/app/dl.sh")

	if rec := f.do(t, f.admin, http.MethodPost, path, "p-bob", `{"event":"checkpoint","checkpoint":"`+commit+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("someone else's report %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPost, path, "p-alice", `{"event":"checkpoint","checkpoint":"`+commit+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("checkpoint %d %s", rec.Code, rec.Body)
	}
	rec := f.do(t, f.admin, http.MethodPost, path, "p-alice", `{"event":"undo","checkpoint":"`+commit+`","removed":["`+digest+`"]}`)
	var got struct {
		Forgotten       int  `json:"forgotten"`
		CheckpointKnown bool `json:"checkpoint_known"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || !got.CheckpointKnown {
		t.Fatalf("undo %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"event":"revert"}`, `{"event":"undo","extra":1}`, `{"event":"checkpoint","checkpoint":"` + commit + `","removed":["` + digest + `"]}`, `not json`} {
		if rec := f.do(t, f.admin, http.MethodPost, path, "p-alice", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := f.do(t, f.admin, http.MethodPost, path, "p-alice", `{"event":"undo","removed":["/work/app/dl.sh"]}`); rec.Code != http.StatusBadGateway ||
		!strings.Contains(rec.Body.String(), "chain_report_failed") {
		t.Fatalf("leader refusal %d %s", rec.Code, rec.Body)
	}
	f2 := newSubstrateFixture(t)
	if rec := f2.do(t, f2.admin, http.MethodPost, path, "p-alice", `{"event":"checkpoint","checkpoint":"`+commit+`"}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("no chain state %d %s", rec.Code, rec.Body)
	}
}

// GAP-0476: an undo is a log.sandbox.lifecycle row (reverting, trigger
// undo); a checkpoint is not a transition.
func TestGAP0476UndoIsALifecyclePhase(t *testing.T) {
	if phase, trigger, ok := substrateLifecyclePhase(chainstate.LifecycleUndone); !ok || phase != "reverting" || trigger != "undo" {
		t.Fatalf("undone: %q %q %v", phase, trigger, ok)
	}
	if _, _, ok := substrateLifecyclePhase(chainstate.LifecycleCheckpointed); ok {
		t.Fatal("a checkpoint has a phase")
	}
}
