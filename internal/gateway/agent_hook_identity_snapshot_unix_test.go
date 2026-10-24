// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	osuser "os/user"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAcceptedHookReadsVerifiedIdentityOnce(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	hook := func(string) { reads.Add(1) }
	agentIdentityUPNReadHook.Store(&hook)
	t.Cleanup(func() { agentIdentityUPNReadHook.Store(nil) })

	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(managedHookBody("identity-once", "PreToolUse")))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{
		UID: os.Getuid(), Name: current.Username, Home: current.HomeDir,
	}))
	reply := httptest.NewRecorder()
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), `"action":"allow"`) {
		t.Fatalf("hook answer = %d %s", reply.Code, reply.Body.String())
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("accepted hook read verified UPN %d times; want one request-scoped identity snapshot", got)
	}
}

func TestProfiledAcceptedHookReadsVerifiedIdentityOnce(t *testing.T) {
	for _, matchAgent := range []bool{false, true} {
		name := "default profile"
		if matchAgent {
			name = "agent assignment"
		}
		t.Run(name, func(t *testing.T) {
			f := newManagedHookAuditFixture(t, nil)
			current, err := osuser.Current()
			if err != nil {
				t.Fatal(err)
			}
			peer := withManagedHookPeer(t.Context(), managedHookPeer{
				UID: os.Getuid(), Name: current.Username, Home: current.HomeDir,
			})
			cfg := f.api.scannerCfg
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"base": {Mode: "observe"}, "assigned": {Mode: "observe"},
			}
			cfg.Guardrail.DefaultProfile = "base"
			if matchAgent {
				id := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "claudecode"}).ID
				if id == "" {
					t.Fatal("verified peer has no agent identity")
				}
				cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
					Profile: "assigned", Match: config.ProfileMatch{Agents: []string{id}},
				}}
			}
			f.api.initGuardrailProfiles(cfg)
			if f.api.guardrailProfileSet() == nil {
				t.Fatal("configured profiles were not loaded")
			}
			t.Cleanup(func() { f.api.setGuardrailProfiles(nil) })
			wantProfile := "base"
			if matchAgent {
				wantProfile = "assigned"
			}
			profileCtx := f.api.withGuardrailProfileDecision(withProfilePath(peer, profilePathHook), "claudecode")
			if got := f.api.resolveProfile(profileCtx).Name; got != wantProfile {
				t.Fatalf("verified hook profile = %q; want %q", got, wantProfile)
			}
			var reads atomic.Int64
			hook := func(string) { reads.Add(1) }
			agentIdentityUPNReadHook.Store(&hook)
			t.Cleanup(func() { agentIdentityUPNReadHook.Store(nil) })

			for call := 1; call <= 2; call++ {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
					strings.NewReader(managedHookBody(name+string(rune('0'+call)), "PreToolUse")))
				request.Header.Set("Content-Type", "application/json")
				request = request.WithContext(peer)
				reply := httptest.NewRecorder()
				f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
				if reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), `"action":"allow"`) {
					t.Fatalf("hook %d answer = %d %s", call, reply.Code, reply.Body.String())
				}
				if got := reads.Load(); got != int64(call) {
					t.Fatalf("%d accepted profiled hooks read verified UPN %d times; want one fresh read per hook", call, got)
				}
			}
		})
	}
}

func TestAgentIdentityDefersLegacyOwnerCheckUntilProfileNeedsIt(t *testing.T) {
	agentIdentityTestSetup(t)
	previousIncarnation, previousBound := agentIdentityIncarnation, legacyAgentOwnerBound
	t.Cleanup(func() {
		agentIdentityIncarnation, legacyAgentOwnerBound = previousIncarnation, previousBound
	})
	agentIdentityIncarnation = func(string) string { return "new-account" }
	var checks int
	legacyAgentOwnerBound = func(string, string) bool { checks++; return true }
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 424242, Name: "alice", Home: "/home/alice"})
	facts := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" || facts.LegacyID == "" {
		t.Fatalf("expected current and legacy identities, got %+v", facts)
	}
	if checks != 0 {
		t.Fatalf("resolved identity checked legacy owner %d times without a matching legacy assignment", checks)
	}
}
