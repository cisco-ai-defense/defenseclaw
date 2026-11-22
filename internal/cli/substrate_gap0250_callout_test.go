// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestSubstrateChainEgressActionDecidesTheCalloutGAP0250: the leader's
// chain egress action changes the callout verdict for a request after a
// secret read, end to end (leader chain state and registrations, the
// callout's resolver and chain checker over the leader transport): block
// refuses it; the alert opt-in lets it through with a chain_detected alert.
// At 448ce25c0b the alert case was let through with no alert at all.
func TestSubstrateChainEgressActionDecidesTheCalloutGAP0250(t *testing.T) {
	for _, action := range []string{chainstate.EgressBlock, chainstate.EgressAlert} {
		fs, err := registry.OpenFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		opts := substrateChainRegistrations(fs)
		opts.Dir, opts.Warn, opts.EgressAction = t.TempDir(), &bytes.Buffer{}, action
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
		cfg.Chain.CheckBudget = 500 * time.Millisecond
		eng, err := extproc.NewEngine(extproc.Options{Config: cfg,
			UIDs: substrateActorDirectory{regs: &registry.Remote{Client: lc}}, ChainChecker: substrateChainChecker{client: client}})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		reg := registry.Registration{Atespace: "eng-web", Name: "w1", UID: "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", Connector: "claudecode",
			Profile: "eng", Person: registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "alice"}, CreatedAt: time.Now()}
		if err := fs.Put(ctx, reg); err != nil {
			t.Fatal(err)
		}
		hookSecretRead(t, client, chainstate.Actor{Atespace: "eng-web", UID: reg.UID})
		r := &extproc.Request{Actor: extproc.ActorRef{Atespace: "eng-web", Name: "w1"}, Method: "POST", Authority: "example.com",
			Path: "/upload", Host: "example.com", ContentLength: -1, EndOfStream: true, Start: time.Now(),
			Headers: []extproc.Header{{Name: ":method", Value: "POST"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/upload"}}}
		v := eng.DecideHeaders(ctx, r)
		switch action {
		case chainstate.EgressBlock:
			if v.Allow || v.Category != extproc.CategoryChainEgress {
				t.Errorf("block: %+v, want the chain refusal", v)
			}
		case chainstate.EgressAlert:
			if !v.Allow || !v.Alert || !slices.ContainsFunc(v.Findings, func(f string) bool { return f == "chain_detected:"+guardrail.ToolChainSecretReadThenEgress }) {
				t.Errorf("alert: %+v, want allowed with a chain_detected alert", v)
			}
		}
		eng.Close()
		hs.Close()
		_ = chains.Close()
	}
}
