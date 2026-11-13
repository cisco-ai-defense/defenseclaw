// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// newTestChainLeaderService is newTestChainLeader with the leader's
// Service, so a test can make the callout's chain check (ChainEgress).
func newTestChainLeaderService(t *testing.T) (*chainstate.Service, *chainstate.Client) {
	t.Helper()
	svc, err := chainstate.New(chainstate.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	srv := httptest.NewServer(ls)
	t.Cleanup(func() { srv.Close(); _ = svc.Close() })
	return svc, &chainstate.Client{Leader: &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Second}}
}

// TestSubstrateHookSecretReadRefusesTheFirstEgressGAP0179 drives the real
// hook path of a Substrate actor: Claude Code's PreToolUse and PostToolUse
// for `cat ~/.aws/credentials` through the actor listener, which records
// the read in the actor window with a prepare and a resolve (no observe),
// then the callout's chain check of the actor's next request. The read
// counts from PreToolUse (the command can send the file while it runs),
// and still after PostToolUse; a benign actor's egress passes.
func TestSubstrateHookSecretReadRefusesTheFirstEgressGAP0179(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	svc, chains := newTestChainLeaderService(t)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Chains = chains })
	// A gateway replica has its audit store: the hook's correlation (its
	// semantic event and connector instance) needs it.
	f.api.store, f.api.logger = testStoreAndV8Logger(t)
	ctx := context.Background()
	egress := chainstate.EgressRequest{Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "example.com", Method: "POST"}
	check := func(when string, wantDeny bool) {
		t.Helper()
		v, err := svc.Egress(ctx, egress)
		if err != nil || v.Deny != wantDeny || (wantDeny && v.Rule != guardrail.ToolChainSecretReadThenEgress) {
			t.Errorf("%s: egress %+v err=%v, want deny=%v", when, v, err, wantDeny)
		}
	}
	hook := func(ev map[string]any) {
		t.Helper()
		ev["cwd"] = "/work"
		rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", envelope("claudecode", ev))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", ev["hook_event_name"], rec.Code, rec.Body)
		}
	}

	check("before any hook", false)
	hook(claudeToolEvent("PreToolUse", "s1", "list-1", "ls -la"))
	hook(claudeToolResult("PostToolUse", "s1", "list-1"))
	check("after a benign command", false)

	hook(claudeToolEvent("PreToolUse", "s1", "read-1", "cat ~/.aws/credentials"))
	check("while the secret read runs", true)
	hook(claudeToolResult("PostToolUse", "s1", "read-1"))
	check("first egress after the secret read", true)
	check("second egress after the secret read", true)
}
