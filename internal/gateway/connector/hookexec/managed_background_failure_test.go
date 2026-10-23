// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0910: a gateway outage may skip OpenCode's background events, but
// they did not admit a tool call. Only the pre-tool boundary is a delivery
// decision that belongs in the fail-open or fail-closed report.
func TestManagedOpenCodeBackgroundOutageRecordsDiagnosticNotFailOpen(t *testing.T) {
	for _, event := range []string{
		"defenseclaw.plugin.loaded", "session.created", "session.updated", "session.status",
		"session.idle", "session.compacted", "session.error", "session.deleted", "tool.execute.after",
		"tool.execute.before",
	} {
		t.Run(event, func(t *testing.T) {
			var home string
			result := run(t, "opencode", ok(`{"action":"allow"}`), func(o *Options) {
				o.ManagedEnterprise = true
				o.ManagedStandalone = true
				o.FailMode = "closed"
				o.ManagedRuntimeFailure = managedGatewayNotRunningReason
				o.ManagedServiceUID = 0
				o.Event = event
				o.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":%q,"event_type":%q,"tool_name":"bash","tool_input":{}}`, event, event))
				home = o.Home
				o.FailureLogHome = userLogHome(home)
			})
			raw, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
			if err != nil {
				t.Fatalf("read hook-failures: %v; result=%+v", err, result)
			}
			var record struct {
				Event, Outcome string
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &record); err != nil {
				t.Fatalf("decode hook-failures %q: %v", raw, err)
			}
			if record.Event != event {
				t.Fatalf("event=%q, want %q", record.Event, event)
			}
			if event == "tool.execute.before" {
				if record.Outcome != "fail_closed" || !blocked(result) {
					t.Fatalf("foreground tool: record=%+v result=%+v, want a closed block", record, result)
				}
				return
			}
			if record.Outcome != "diagnostic" || strings.Contains(result.stderr, "WARNING hook fail-open") {
				t.Fatalf("background event: record=%+v stderr=%q, want a diagnostic without a fail-open warning", record, result.stderr)
			}
		})
	}
}
