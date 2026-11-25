// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0923Hook sends one Claude Code PreToolUse Bash hook for command from a
// sandbox actor in the guest home and returns its HTTP status.
func gap0923Hook(api *APIServer, ctx context.Context, command, id string) int {
	body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0923",
		"cwd": sandboxauth.SandboxHome, "tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": id})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
	return rec.Code
}

// TestGAP0923GuestHookAllocations pins the memory one sandbox actor hook
// takes on compound calls the whole-call analysis does not read in full. The
// guest placement walked such a call twice a hook (the placed children and
// the sandbox hook-config guard), with four SimpleCommands passes where one
// input needs one, and the actor ran 1.2-2.1x rel/1.0.11 on and-chains,
// linear in the segments (substrate-1 GAP-0923, GAP-1028). The bounds are
// set from measured numbers, about midway between the tree before the
// fix (17.9, 11.4, 21.3, 6.3 and 7.0 MB a hook) and after it (13.8, 8.2,
// 14.9, 4.8 and 5.5 MB): the walk made once a reading, one parser per
// grammar reused, each cd text read once and each segment asked once a
// hook whether it names a relative operand.
//
// The bounds are for a plain build. The race detector instruments every
// allocation and about doubles TotalAlloc a hook (and-chain 20: 30.3 MB, bound
// 15.5; function cd make: 7.7 MB, bound 6.2; FOLD-2 gateway -race, GAP-1059).
// Under -race the hooks still run, so the detector covers the placement
// walk, and the byte figure is logged, but it is not asserted
// (hookAnswerRaceBuild). A plain build keeps every bound.
func TestGAP0923GuestHookAllocations(t *testing.T) {
	pack := "default"
	installToolCallCorpusProfileConnector(t, "claudecode", pack)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, dir := range []string{"src", "build", ".claude", ".defenseclaw"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	binding := sandboxTestBinding("claudecode")
	actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
	chain := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("echo step%d", i)
		}
		return strings.Join(parts, " && ")
	}
	shapes := []struct {
		name    string
		command string
		bound   uint64
	}{
		{"and-chain 20", chain(20), 15_500_000},
		{"and-chain 40", chain(40), 9_500_000},
		{"and-chain 80", chain(80), 17_000_000},
		{"case cd", `case "$1" in a) cd src;; *) cd build;; esac; make`, 5_400_000},
		{"function cd make", `build() { cd src && make; }; build; cd ..`, 6_200_000},
	}
	const hooks = 20
	for _, shape := range shapes {
		for i := 0; i < 3; i++ {
			if code := gap0923Hook(api, actor, shape.command, fmt.Sprintf("w%d", i)); code != http.StatusOK {
				t.Fatalf("%s: hook status %d", shape.name, code)
			}
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < hooks; i++ {
			gap0923Hook(api, actor, shape.command, fmt.Sprintf("m%d", i))
		}
		runtime.ReadMemStats(&after)
		perHook := (after.TotalAlloc - before.TotalAlloc) / hooks
		objects := (after.Mallocs - before.Mallocs) / hooks
		t.Logf("GAP0923ALLOC %s: %d bytes %d objects a hook", shape.name, perHook, objects)
		if perHook > shape.bound && !hookAnswerRaceBuild {
			t.Errorf("%s: a sandbox actor hook allocated %.2f MB, over %.2f MB (substrate-1 GAP-0923)",
				shape.name, float64(perHook)/1e6, float64(shape.bound)/1e6)
		}
	}
}
