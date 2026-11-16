// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"encoding/json"
	"testing"
)

// p0-round GAP-1389, macOS leg: an eslogger message names the account of
// its process by the effective uid in the audit token, so a session that
// exits before the next poll still names who ran it. Before the fix the
// macOS source decoded the euid and dropped it: the event named no account.
func TestEndpointSecurityEventsNameTheEffectiveUIDAndItsAccount(t *testing.T) {
	t.Parallel()
	names := map[int]string{501: "dcr-mac1"}
	owner := func(uid int) string { return names[uid] }
	watched := []string{"/Users/dcr-mac1/.claude"}
	for _, tc := range []struct {
		name  string
		raw   string
		uid   int
		user  string
		noUID bool
	}{
		{name: "exec names the new image's account", raw: `{"event_type": 9, "process": {"audit_token": {"pid": 700, "euid": 501}, "ppid": 1,
			"executable": {"path": "/bin/zsh"}}, "event": {"exec": {"target": {"audit_token": {"pid": 700, "euid": 501},
			"executable": {"path": "/Users/dcr-mac1/.local/bin/claude"}}, "args": ["claude"]}}}`, uid: 501, user: "dcr-mac1"},
		{name: "a setuid target is its new account, not the caller's", raw: `{"event_type": 9, "process": {"audit_token": {"pid": 701, "euid": 501}, "ppid": 700,
			"executable": {"path": "/bin/zsh"}}, "event": {"exec": {"target": {"audit_token": {"pid": 701, "euid": 0},
			"executable": {"path": "/usr/bin/sudo"}}, "args": ["sudo", "-i"]}}}`, uid: 0, user: ""},
		{name: "a file write names its writer", raw: `{"event_type": 13, "process": {"audit_token": {"pid": 700, "euid": 501}, "ppid": 1,
			"executable": {"path": "/Users/dcr-mac1/.local/bin/claude"}}, "event": {"create": {"destination": {"existing_file":
			{"path": "/Users/dcr-mac1/.claude/settings.json"}}}}}`, uid: 501, user: "dcr-mac1"},
		{name: "exit names the exiting process", raw: `{"event_type": 15, "process": {"audit_token": {"pid": 700, "euid": 501}, "ppid": 1,
			"executable": {"path": "/Users/dcr-mac1/.local/bin/claude"}}, "event": {"exit": {}}}`, uid: 501, user: "dcr-mac1"},
		{name: "a uid no account holds names no account", raw: `{"event_type": 15, "process": {"audit_token": {"pid": 702, "euid": 777}, "ppid": 1,
			"executable": {"path": "/bin/sh"}}, "event": {"exit": {}}}`, uid: 777, user: ""},
		{name: "a token without an euid is not root", raw: `{"event_type": 15, "process": {"audit_token": {"pid": 703}, "ppid": 1,
			"executable": {"path": "/bin/sh"}}, "event": {"exit": {}}}`, noUID: true},
	} {
		var message esMessage
		if err := json.Unmarshal([]byte(tc.raw), &message); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		event, ok := translateES(message, watched, owner)
		if !ok {
			t.Fatalf("%s: the message did not translate", tc.name)
		}
		if tc.noUID {
			if event.UID != nil || event.User != "" {
				t.Fatalf("%s: uid %v user %q, want none", tc.name, event.UID, event.User)
			}
			continue
		}
		if event.UID == nil || *event.UID != tc.uid || event.User != tc.user {
			t.Fatalf("%s: uid %v user %q, want uid %d user %q", tc.name, event.UID, event.User, tc.uid, tc.user)
		}
	}
}
