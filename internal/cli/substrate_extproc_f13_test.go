// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestSubstrateRecreatedActorEgressIsChainChecked is GAP-0234 end to end,
// on the shipped wiring: the leader's registrations, chain state and
// substrateChainRegistrations, the callout's resolver and chain checker
// over the leader transport, and the callout engine with the default
// uid.cache_ttl. A same-name actor is deleted and created again; within the
// cache TTL the new incarnation reads a secret and egresses. Its egress is
// refused (secret-read-then-egress) on an OSS install and a managed one.
func TestSubstrateRecreatedActorEgressIsChainChecked(t *testing.T) {
	for _, managed := range []bool{false, true} {
		fs, err := registry.OpenFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		opts := substrateChainRegistrations(fs)
		opts.Dir, opts.Warn = t.TempDir(), &bytes.Buffer{}
		chains, err := chainstate.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		srv := &leader.Server{IsLeader: func() bool { return true }}
		registry.Serve(srv, fs)
		chains.Register(srv)
		hs := httptest.NewServer(srv)
		lc := &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}
		client := &chainstate.Client{Leader: lc}

		cfg, err := extproc.ParseConfig(nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Managed = managed
		cfg.Chain.CheckBudget = 500 * time.Millisecond // the check, not its latency, is under test
		eng, err := extproc.NewEngine(extproc.Options{Config: cfg,
			UIDs:         substrateActorDirectory{regs: &registry.Remote{Client: lc}},
			ChainChecker: substrateChainChecker{client: client}})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		person := registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "alice"}
		first := registry.Registration{Atespace: "eng-web", Name: "w1", UID: "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a",
			Connector: "claudecode", Profile: "eng", Person: person, CreatedAt: time.Now().Add(-time.Minute)}
		if err := fs.Put(ctx, first); err != nil {
			t.Fatal(err)
		}
		egress := func() extproc.Verdict {
			r := &extproc.Request{Actor: extproc.ActorRef{Atespace: "eng-web", Name: "w1"}, Method: "POST", Authority: "example.com",
				Path: "/upload", Host: "example.com", ContentLength: -1, EndOfStream: true, Start: time.Now(),
				Headers: []extproc.Header{{Name: ":method", Value: "POST"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/upload"}}}
			return eng.DecideHeaders(ctx, r)
		}
		if v := egress(); !v.Allow {
			t.Fatalf("managed=%v first incarnation, nothing read: %+v", managed, v)
		}

		// Deleted (the controller's tombstone), created again under the same
		// name: a new UID. The callout's cache still names the first.
		first.Deleted = true
		if err := fs.Put(ctx, first); err != nil {
			t.Fatal(err)
		}
		second := first
		second.UID, second.Deleted, second.Key, second.CreatedAt = "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b", false, "", time.Now()
		if err := fs.Put(ctx, second); err != nil {
			t.Fatal(err)
		}
		hookSecretRead(t, client, chainstate.Actor{Atespace: "eng-web", UID: second.UID})

		if v := egress(); v.Allow || v.Category != extproc.CategoryChainEgress {
			t.Fatalf("managed=%v recreated actor egress after a secret read: %+v, want a chain refusal", managed, v)
		}
		eng.Close()
		hs.Close()
		_ = chains.Close()
	}
}

// hookSecretRead observes a secret read in the actor's windows, as the
// gateway's chain stage does for a hook.
func hookSecretRead(t *testing.T, c *chainstate.Client, a chainstate.Actor) {
	t.Helper()
	bit, ok := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	if !ok {
		t.Fatal("no secret-read step")
	}
	p := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: bit, EnforcementStepMask: bit}
	if def, _ := guardrail.ToolChainDefinitionByID(guardrail.ToolChainSecretReadThenEgress); def.RequiresEnforcementJoin || def.RequiresExactJoin {
		index, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
		p.EnforcementJoinDigests[index] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	id, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(id))
	in := audit.ToolChainObserveInput{SemanticEventID: id, InputFingerprint: hex.EncodeToString(sum[:]),
		RulesetFingerprint: "1111111111111111111111111111111111111111111111111111111111111111", Projection: p, DenyEligible: true}
	for _, scope := range []chainstate.Scope{chainstate.ScopeSession, chainstate.ScopeActor} {
		b, err := c.Bind(a, scope, "claudecode", "s1", "PreToolUse")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Observe(context.Background(), in); err != nil {
			t.Fatalf("%s observe: %v", scope, err)
		}
	}
}
