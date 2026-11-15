// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// The explain view reads a session's label, counts and evictions while hooks
// step the same session. Run under -race, this fails if any of those reads
// skips the state's lock.
func TestSecretFlowExplainViewRace(t *testing.T) {
	withSecretFlowGeneration(t, "shadow", "shadow")
	const sid = "r2-view-race"
	ctx := ContextWithSessionID(context.Background(), sid)
	req := trustedActionRequest{
		Input:     actionfacts.Input{Tool: "Bash", Command: "cat .env", CWD: "/home/u/p", ActiveHome: "/home/u"},
		Connector: "claudecode", EnforcementCapable: true,
	}
	runSecretFlowShadow(ctx, req)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				runSecretFlowShadow(ctx, req)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 400; j++ {
				if v := secretFlowSessions.view(sid); !v.Found {
					t.Error("session vanished")
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				addSecretFlowResultValues(context.Background(), agentHookRequest{
					ConnectorName: "claudecode", HookEventName: "PostToolUse", SessionID: sid, ToolName: "Bash",
					ToolArgs: []byte(`{"command":"cat .env"}`), CWD: "/home/u/p",
					Payload: map[string]interface{}{"tool_response": "API_KEY=sflow_race_0123456789abcdefQRS\n"},
				})
			}
		}()
	}
	wg.Wait()
}

// The case fold the effect model needs on a case-insensitive host is switched
// on by the gateway: Windows paths always, and a macOS host. Other hosts keep
// exact case.
func TestSecretFlowCaseFoldWired(t *testing.T) {
	for _, c := range []struct {
		goos   string
		flavor effects.Flavor
		want   bool
	}{
		{"linux", effects.FlavorPOSIX, false},
		{"darwin", effects.FlavorPOSIX, true},
		{"windows", effects.FlavorWindows, true},
		{"linux", effects.FlavorWindows, true},
	} {
		if got := secretFlowCaseInsensitiveFor(c.goos, c.flavor); got != c.want {
			t.Errorf("%s/%s: got %v want %v", c.goos, c.flavor, got, c.want)
		}
	}
	// On macOS an upper-case spelling of a credential file is read as that
	// file: the extractor marks the target folded, and the label step uses it.
	opts := effects.Options{Flavor: effects.FlavorPOSIX, Home: "/Users/u", CWD: "/Users/u/p", CaseInsensitive: secretFlowCaseInsensitiveFor("darwin", effects.FlavorPOSIX)}
	res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Tool: "Bash", Command: "cat .ENV"}, opts)
	folded := false
	for _, e := range res.Effects {
		if e.Kind == effects.KindRead && e.Target.CaseFold {
			folded = true
		}
	}
	if !folded {
		t.Fatalf("the read of .ENV is not case-folded on a darwin host")
	}
}
