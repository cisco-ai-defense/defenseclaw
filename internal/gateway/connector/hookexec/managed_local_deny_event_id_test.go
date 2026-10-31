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

// mgmt-p1 GAP-0134: a managed hook that blocked a call itself while the
// gateway was down answered with no audit event id, and no audit row held
// the call. The hook now gives the refusal an event id, writes it in the
// account's hook-failure row and names it in its answer. A fail-open row,
// and a call whose row could not be written, name none.
func TestManagedLocalDenyNamesTheEventIDOfItsRecord(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"closed", "open"} {
			userHome := t.TempDir()
			r := run(t, connector, &stubRT{err: errManagedGatewayNotRunning}, func(opts *Options) {
				opts.ManagedEnterprise = true
				opts.ManagedStandalone = true
				opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
				opts.FailMode = mode
				opts.FailureLogHome = func() string { return userHome }
			})
			data, err := os.ReadFile(filepath.Join(userHome, "logs", "hook-failures.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]string
			if err := json.Unmarshal(bytes.TrimSpace(data), &row); err != nil {
				t.Fatal(err)
			}
			id := row["event_id"]
			if row["outcome"] != "fail_closed" {
				if id != "" || strings.Contains(r.stderr, "event_id=") {
					t.Fatalf("%s %s: a %s row names an event id: row %v stderr %q", connector, mode, row["outcome"], row, r.stderr)
				}
				continue
			}
			if parsed, err := uuid.Parse(id); err != nil || parsed.Version() != 7 {
				t.Fatalf("%s: row event_id %q is not a UUIDv7 (%v): %v", connector, id, err, row)
			}
			if !blocked(r) || !strings.Contains(r.stdout+r.stderr, "event_id="+id) {
				t.Fatalf("%s: answer does not name event_id %s: %+v", connector, id, r)
			}
			if got := withoutLocalDenyEventID(r.stderr); strings.Contains(got, "event_id=") {
				t.Fatalf("%s: withoutLocalDenyEventID left the id line: %q", connector, got)
			}
		}
	}
	// No diagnostic directory: no row, so no id is named.
	missing := filepath.Join(t.TempDir(), "absent")
	r := run(t, "claudecode", &stubRT{err: errManagedGatewayNotRunning}, func(opts *Options) {
		opts.ManagedEnterprise = true
		opts.ManagedStandalone = true
		opts.ManagedUnixSocket = "/not-used-by-stub/hook.sock"
		opts.FailMode = "closed"
		opts.FailureLogHome = func() string { return missing }
	})
	if !blocked(r) || strings.Contains(r.stdout+r.stderr, "event_id=") {
		t.Fatalf("a call without a written row named an event id: %+v", r)
	}
}

// withoutLocalDenyEventID drops the hook's event_id line (logHookFailure)
// from stderr, so a test of the block text compares the text alone.
func withoutLocalDenyEventID(stderr string) string {
	var kept []string
	for _, line := range strings.SplitAfter(stderr, "\n") {
		if !strings.HasPrefix(line, "defenseclaw: event_id=") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}
