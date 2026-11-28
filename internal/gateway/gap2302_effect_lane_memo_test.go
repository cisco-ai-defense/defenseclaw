// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// rel-1-0-10:GAP-2302: the effects lane is live (ON) by default since DET111
// step 3 and runs on the hook's path. On a POSIX host the package link
// resolver keeps no memory (hookpaths.memoReads), and the lane walked every
// target on disk once per protected set and again for its hard link
// identity, beside the readers' own walk of the same paths through the call's
// target memo: L1 t-long (60 statements on a linked home) took 1.17x the
// 1.0.10 hook p99. The lane now walks through the call's memo; its answers
// are the same.

// gap2302LinkedHome is a home reached through a link, with a project folder
// and a notes file, and a call of n statements that each make, copy into and
// remove a scratch folder of the project.
func gap2302LinkedHome(t *testing.T, n int) (home, command string) {
	t.Helper()
	root := t.TempDir()
	real := filepath.Join(root, "realhome")
	if err := os.MkdirAll(filepath.Join(real, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "proj", "notes"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(root, "linkhome")
	if err := os.Symlink(real, home); err != nil {
		t.Fatal(err)
	}
	statements := make([]string, 0, n)
	for i := 0; i < n; i++ {
		statements = append(statements, fmt.Sprintf("cd ~/proj && mkdir -p out%d && cp notes out%d/ && rm -r out%d", i, i, i))
	}
	return home, strings.Join(statements, "; ")
}

func gap2302Generation(t *testing.T, effects string) {
	t.Helper()
	previous := liveGeneration.Load()
	cfg := &config.Config{}
	if effects != "" {
		cfg.Guardrail.Cascade.SetLane(config.CascadeLaneEffects, effects)
	}
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(previous) })
}

// TestGAP2302EffectLaneWalksThroughTheCallMemo: a run of the lane through a
// memo reads a fraction of the file system the run without one reads, and
// every run grades the call as the run without a memo does.
func TestGAP2302EffectLaneWalksThroughTheCallMemo(t *testing.T) {
	gap2302Generation(t, "")
	home, command := gap2302LinkedHome(t, 8)
	request := trustedActionRequest{
		Input: actionfacts.Input{
			Command: command, ActiveHome: home, CWD: filepath.Join(home, "proj"),
			DialectHint: actionfacts.DialectPOSIX,
		},
		Connector: "claudecode", EnforcementCapable: true,
	}
	run := func(request trustedActionRequest) (EffectShadowResult, int64) {
		before := workcount.Take()
		res := computeEffectShadow(request, effectRulesOn, tierRestricted)
		res.CostUS = 0
		return res, before.Since(workcount.WordLookup)
	}
	bare, bareLookups := run(request)
	request.targetMemo = hookpaths.NewTargetMemo()
	cold, coldLookups := run(request)
	warm, warmLookups := run(request)
	t.Logf("lookups: no memo %d, cold memo %d, warm memo %d", bareLookups, coldLookups, warmLookups)
	if !reflect.DeepEqual(cold, bare) || !reflect.DeepEqual(warm, bare) {
		t.Fatalf("the memo changed the grade:\n no memo %+v\n cold    %+v\n warm    %+v", bare, cold, warm)
	}
	// 5e93cafe74: 3160 lookups with or without a memo; the fix: 72 cold, 40
	// warm (the reads the memo does not keep, a missing folder's parents).
	if coldLookups*10 > bareLookups || warmLookups > coldLookups {
		t.Fatalf("lookups: no memo %d, cold memo %d, warm memo %d: the lane must walk through the call's memo", bareLookups, coldLookups, warmLookups)
	}
}

// TestGAP2302HookEffectLaneAddsNoWalks: the hook judges the call with the
// lane on in about the file system lookups it makes with the lane off, and
// with the same verdict.
func TestGAP2302HookEffectLaneAddsNoWalks(t *testing.T) {
	home, command := gap2302LinkedHome(t, 20)
	t.Setenv("HOME", home)
	judge := func(effects string) (string, int64) {
		gap2302Generation(t, effects)
		api := gap0589TierAPI(t, "claudecode", "default", false, bounded.TierDefault)
		before := workcount.Take()
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap2302", ToolName: "Bash", CWD: filepath.Join(home, "proj"),
			ToolInput: map[string]interface{}{"command": command},
		})
		return resp.Action + "/" + resp.Severity, before.Since(workcount.WordLookup)
	}
	offAction, off := judge("off")
	onAction, on := judge("")
	t.Logf("hook lookups: lane off %d, lane on %d", off, on)
	if onAction != offAction {
		t.Fatalf("lane on verdict %q, lane off %q: the benign call must judge the same", onAction, offAction)
	}
	// 5e93cafe74: 35340 off, 51020 on; the fix: 35440 on.
	if on > off+off/10 {
		t.Fatalf("the hook made %d lookups with the lane on, %d with it off: the lane walks again what the readers walked", on, off)
	}
}
