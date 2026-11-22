// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10 GAP-1304: the teardown of a configured connector failed on a file
// only this install's backup records name that is not a JSON object, on every
// path. The gateway's boot teardowns (guardrail disabled, a removed connector,
// the lock-only orphan reconcile) run that teardown, so the gateway reported
// "connector teardown incomplete for: kiro" on every start until the user
// fixed or deleted the file. Only `connector teardown` and `connector verify`
// report the file now; a boot teardown logs it and goes on, and the boot
// reclaim finishes the cleanup once the file can be read.
func TestKiroBootTeardownLogsARecordedFileItCannotParseAndGoesOn(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	root := t.TempDir()
	dataB := filepath.Join(root, "b", ".defenseclaw")
	w1 := filepath.Join(root, "w1")
	for _, dir := range []string{dataB, w1} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	mine := kiroHookACustomAgentThenSwitchAway(t, conn, opts, home)
	own := conn.installHookCommands(opts)
	opts.WorkspaceDir = ""
	w1Hooks := filepath.Join(w1, ".kiro", "hooks", kiroManagedHooksName)
	const broken = `{"hooks": [`
	if err := os.WriteFile(w1Hooks, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	// The boot teardown: the options carry no ReportUnreadableResidue.
	for boot := 1; boot <= 2; boot++ {
		if err := conn.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("boot %d: the teardown failed on the file it cannot parse: %v", boot, err)
		}
		if err := conn.VerifyClean(opts); err != nil {
			t.Fatalf("boot %d: VerifyClean failed on the file it cannot parse: %v", boot, err)
		}
	}
	if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || held {
		t.Errorf("install B's entries stayed in the custom agent: %v, %v", held, err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, []string{kiroUserLint}); err != nil || !held {
		t.Errorf("the user's own hook went: %v, %v", held, err)
	}
	if got, err := os.ReadFile(w1Hooks); err != nil || string(got) != broken {
		t.Errorf("the file it cannot parse changed (%v): %q", err, got)
	}
	names := kiroRecordNames(t, dataB)
	if len(names) != 1 || names[0] != kiroBackupLogicalName(w1Hooks) {
		t.Errorf("Kiro backup records after the boot teardown = %v, want only the record of %s", names, w1Hooks)
	}
	if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || owns {
		t.Errorf("the record of a file that cannot be read starts the boot reclaim: %v, %v", owns, err)
	}

	// The user fixes the file: its record is pending again, so the boot
	// reclaim takes install B's entry out of it and drops the record.
	fixed := map[string]interface{}{"hooks": []interface{}{
		kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", conn.hookCommandForV3Surface(opts)),
		kiroV3Entry("lint", "PostToolUse", kiroUserLint),
	}}
	if err := writeJSONObject(w1Hooks, fixed); err != nil {
		t.Fatal(err)
	}
	if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || !owns {
		t.Fatalf("the boot reclaim does not finish the cleanup once the file parses: %v, %v", owns, err)
	}
	reclaim := opts
	reclaim.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), reclaim); err != nil {
		t.Fatalf("the boot reclaim once the file parses: %v", err)
	}
	if held, err := kiroV3FileHoldsCommand(w1Hooks, conn.installHookCommands(opts)); err != nil || held {
		t.Errorf("install B's entry stayed in the fixed file: %v, %v", held, err)
	}
	if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{kiroUserLint}); err != nil || !held {
		t.Errorf("the user's own hook went from the fixed file: %v, %v", held, err)
	}
	if names := kiroRecordNames(t, dataB); len(names) != 0 {
		t.Errorf("the finished reclaim kept Kiro backup records %v", names)
	}
}
