// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-2463: an earlier release registered the Hermes matrix without the
// fail_closed setting Setup now puts on pre_tool_call. Those hooks still run,
// so a managed account whose session is disconnected during an upgrade is
// guarded by them (enrolled with an older hook matrix), not unguarded. The
// check accepts exactly that difference and nothing else.
func TestHermesRegistrationLackingOnlyFailClosedIsTheEarlierMatrix(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:      filepath.Join(root, ".defenseclaw"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		AgentVersion: "0.21.5",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if earlier, err := HookRegistrationLacksOnlyFailClosed(conn, opts); err != nil || earlier {
		t.Fatalf("current matrix: HookRegistrationLacksOnlyFailClosed = %v, %v; want false (it is this release's)", earlier, err)
	}

	rewrite := func(change func(hooks map[string]interface{})) {
		t.Helper()
		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]interface{}
		if err := yaml.Unmarshal(body, &document); err != nil {
			t.Fatal(err)
		}
		hooks, _ := document["hooks"].(map[string]interface{})
		change(hooks)
		out, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	firstEntry := func(hooks map[string]interface{}, event string) map[string]interface{} {
		t.Helper()
		entries, _ := hooks[event].([]interface{})
		if len(entries) == 0 {
			t.Fatalf("no %s entry in the rendered config", event)
		}
		entry, _ := entries[0].(map[string]interface{})
		return entry
	}

	// The earlier release's matrix: every entry, pre_tool_call without fail_closed.
	rewrite(func(hooks map[string]interface{}) {
		entry := firstEntry(hooks, "pre_tool_call")
		if _, set := entry["fail_closed"]; !set {
			t.Fatal("this release's pre_tool_call entry has no fail_closed to remove")
		}
		delete(entry, "fail_closed")
	})
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("earlier matrix: OwnedHooksPresent = %v, %v; want false (this release's matrix is absent)", present, err)
	}
	if earlier, err := HookRegistrationLacksOnlyFailClosed(conn, opts); err != nil || !earlier {
		t.Fatalf("earlier matrix: HookRegistrationLacksOnlyFailClosed = %v, %v; want true", earlier, err)
	}

	// Any other difference is not the earlier matrix: an edited entry.
	rewrite(func(hooks map[string]interface{}) {
		firstEntry(hooks, "post_tool_call")["timeout"] = 5
	})
	if earlier, err := HookRegistrationLacksOnlyFailClosed(conn, opts); err != nil || earlier {
		t.Fatalf("edited entry: HookRegistrationLacksOnlyFailClosed = %v, %v; want false", earlier, err)
	}
	// A missing event.
	rewrite(func(hooks map[string]interface{}) {
		firstEntry(hooks, "post_tool_call")["timeout"] = 30
		delete(hooks, "pre_llm_call")
	})
	if earlier, err := HookRegistrationLacksOnlyFailClosed(conn, opts); err != nil || earlier {
		t.Fatalf("missing event: HookRegistrationLacksOnlyFailClosed = %v, %v; want false", earlier, err)
	}

	// Other connectors never report it.
	if earlier, err := HookRegistrationLacksOnlyFailClosed(NewCodexConnector(), SetupOpts{DataDir: opts.DataDir}); err != nil || earlier {
		t.Fatalf("codex: HookRegistrationLacksOnlyFailClosed = %v, %v; want false", earlier, err)
	}
}
