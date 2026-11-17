// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func kiroSetUpForOrphanTest(t *testing.T, dataDir string) (*KiroConnector, SetupOpts, string) {
	t.Helper()
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return conn, opts, home
}

// rel-1-0-10 GAP-1092/GAP-1174: `setup remove kiro` on a connector that is not
// configured asks OrphanedHookConfigPaths for the files that still hold
// DefenseClaw hooks. It matched the command as raw bytes, which a Windows
// -EncodedCommand wrapper (and a data folder name JSON escapes, as here)
// does not survive, so Kiro's hook files were reported "already absent" and stayed.
// The Kiro connector reads its files as decoded entries.
func TestOrphanedKiroHooksAreFoundAsDecodedEntries(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "dc&home")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, opts, home := kiroSetUpForOrphanTest(t, dataDir)
	found, err := OrphanedHookConfigPaths(conn, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(home, "agents", kiroManagedAgentName+".json"),
	} {
		if !slices.Contains(found, want) {
			t.Errorf("orphaned hook files = %v, missing %s", found, want)
		}
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if left, err := OrphanedHookConfigPaths(conn, opts); err != nil || len(left) != 0 {
		t.Fatalf("after teardown orphaned files = %v, err %v", left, err)
	}
}

// rel-1-0-10 GAP-1174: the defenseclaw agent Setup writes is removed with its
// last DefenseClaw hook even when Kiro added metadata of its own to it (it
// kept an orphaned "DefenseClaw-guarded" agent), and kept when its operator
// gave it a setting that changes the agent.
func TestKiroTeardownRemovesTheManagedAgentWithKiroMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		key        string
		value      interface{}
		wantRemain bool
	}{
		"upgrade metadata":     {"kiroUpgrade", map[string]interface{}{"revision": 3}, false},
		"operator mcp servers": {"mcpServers", map[string]interface{}{"x": map[string]interface{}{"command": "y"}}, true},
		"operator prompt":      {"prompt", "be brief", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, opts, home := kiroSetUpForOrphanTest(t, t.TempDir())
			agent := filepath.Join(home, "agents", kiroManagedAgentName+".json")
			cfg, err := readJSONObject(agent)
			if err != nil {
				t.Fatal(err)
			}
			cfg[tc.key] = tc.value
			if err := writeJSONObject(agent, cfg); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			_, statErr := os.Stat(agent)
			if tc.wantRemain && statErr != nil {
				t.Fatalf("an agent with an operator setting %q was removed: %v", tc.key, statErr)
			}
			if !tc.wantRemain && !os.IsNotExist(statErr) {
				t.Fatalf("the managed agent stayed after teardown: %v", statErr)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
		})
	}
}
