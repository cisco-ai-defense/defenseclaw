// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10 GAP-1548: the user chose the agent "mine" before the first
// Setup (the settings backup names it) and switched the default away since.
// Its file then held this install's hook script in an older command form.
// The teardown took only the exact and edited entries out of it, while
// VerifyClean (exactScope) counts the older form as this install's, so the
// removal failed and the gateway could not start until the file was edited by
// hand. The teardown now removes what VerifyClean counts, and only that.
func TestKiroRemoveCleansAnOlderCommandFormFromTheUsersEarlierDefaultAgent(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	root := t.TempDir()
	data := filepath.Join(root, "b", ".defenseclaw")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(home, "agents", "mine.json")
	if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONObject(mine, map[string]interface{}{"name": "mine", "hooks": map[string]interface{}{
		"preToolUse": []interface{}{map[string]interface{}{"command": kiroUserLint, "matcher": "*"}},
	}}); err != nil {
		t.Fatal(err)
	}
	kiroChooseDefaultAgent(t, home, "mine")
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: data, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	kiroChooseDefaultAgent(t, home, "other")
	script := filepath.Join(data, "hooks", kiroHookScriptName)
	otherScript := filepath.Join(root, "a", ".defenseclaw", "hooks", kiroHookScriptName)
	older := []string{
		"/bin/bash '" + script + "' --event preToolUse",
		"/usr/bin/env LC_ALL=C " + script + " --event postToolUse",
	}
	other := "/bin/bash '" + otherScript + "' --event preToolUse"
	if runtime.GOOS == "windows" {
		// A Windows command runs the account's launcher, so ownership stays
		// exact: the older form the account's launcher ran goes, the command
		// of another account's launcher and the user's hook stay.
		var foreign []string
		older, foreign = kiroWindowsOlderAndForeignForms("", KiroHookSurfaceV3)
		other = foreign[0]
		kiroRequireOwned(t, conn, opts, older)
	}
	if err := writeJSONObject(mine, map[string]interface{}{"name": "mine", "hooks": map[string]interface{}{
		"preToolUse": []interface{}{
			map[string]interface{}{"command": kiroUserLint, "matcher": "*"},
			map[string]interface{}{"command": older[0], "matcher": "*"},
			map[string]interface{}{"command": other, "matcher": "*"},
		},
		"postToolUse": []interface{}{map[string]interface{}{"command": older[1], "matcher": "*"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, kiroCommandsSetupWritesNow(conn, opts)); err != nil || held {
		t.Fatalf("the file holds a command Setup writes now (%v, %v); this test checks nothing", held, err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, form := range older {
		if held, err := kiroAgentFileHoldsCommand(mine, []string{form}); err != nil || held {
			t.Errorf("setup remove kiro left this install's %q in the user's earlier default agent: %v, %v", form, held, err)
		}
	}
	for _, keep := range []string{kiroUserLint, other} {
		if held, err := kiroAgentFileHoldsCommand(mine, []string{keep}); err != nil || !held {
			t.Errorf("setup remove kiro took %q, which is not this install's, out of %s: %v, %v", keep, mine, held, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after the removal: %v", err)
	}
}
