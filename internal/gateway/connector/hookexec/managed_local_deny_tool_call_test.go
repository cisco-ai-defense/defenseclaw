// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// BD-BATCH3b: two fixes write the same hook-failure row (logHookFailure).
// rel-1-0-6 GAP-0271 (bd-sweep7b) adds the hook event and the agent's tool
// call id, so a per-user gateway can record the block the agent got under
// the tool id of its own decision row; mgmt-p1 GAP-0134 / rel-1-0-6
// GAP-0297 (bd-p4status) give a managed refusal an event id that the answer
// names. A managed refusal's row carries both, and the answer still names
// the id of that row.
func TestManagedLocalDenyRowNamesItsEventIDAndToolCall(t *testing.T) {
	userHome := t.TempDir()
	r := run(t, "claudecode", &stubRT{err: errManagedGatewayNotRunning}, func(opts *Options) {
		opts.ManagedEnterprise = true
		opts.ManagedStandalone = true
		opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
		opts.FailMode = "closed"
		opts.FailureLogHome = func() string { return userHome }
		opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"s1","tool_use_id":"toolu_1","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	})
	data, err := os.ReadFile(filepath.Join(userHome, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(data), &row); err != nil {
		t.Fatalf("one row expected: %v: %s", err, data)
	}
	if row["outcome"] != "fail_closed" || row["event"] != "PreToolUse" ||
		row["session_id"] != "s1" || row["call_id"] != "toolu_1" || row["tool_id"] != "toolu_1" {
		t.Fatalf("row does not name the blocked tool call: %v", row)
	}
	id := row["event_id"]
	if parsed, err := uuid.Parse(id); err != nil || parsed.Version() != 7 {
		t.Fatalf("row event_id %q is not a UUIDv7 (%v): %v", id, err, row)
	}
	if !blocked(r) || !strings.Contains(r.stdout+r.stderr, "event_id="+id) {
		t.Fatalf("answer does not block and name event_id %s: %+v", id, r)
	}
}
