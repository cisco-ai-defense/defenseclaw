// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNeutralLifecycleEventsExactSets(t *testing.T) {
	want := map[string][]string{
		"claudecode": {"Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd"},
		"codex":      {"Stop", "SubagentStop", "SessionEnd"},
		"cursor":     {"stop", "subagentStop", "sessionEnd"},
		"devin":      {"Stop", "SessionEnd"},
		"copilot":    {"agentStop", "subagentStop", "sessionEnd", "Stop", "SubagentStop"},
		"kiro":       {"Stop"},
		"opencode":   {"session.created", "session.updated", "session.status", "session.idle", "session.compacted", "session.error", "session.deleted"},
	}
	for connector, events := range want {
		if got := NeutralLifecycleEvents(connector); !reflect.DeepEqual(got, events) {
			t.Errorf("%s lifecycle set = %v, want %v", connector, got, events)
		}
		for _, event := range events {
			if !NeutralLifecycleEvent(connector, event) {
				t.Errorf("%s/%s missing from classifier", connector, event)
			}
		}
	}
	for _, tc := range []struct{ connector, event string }{
		{"kiro", "PostToolUse"}, {"kiro", "UserPromptSubmit"},
		{"opencode", "tool.execute.after"}, {"opencode", "tool.execute.before"},
		{"cursor", "beforeShellExecution"}, {"copilot", "preToolUse"},
	} {
		if NeutralLifecycleEvent(tc.connector, tc.event) {
			t.Errorf("%s/%s unexpectedly neutral", tc.connector, tc.event)
		}
	}
	if !NeutralLifecycleEvent("cursor", "SESSIONEND") || NeutralLifecycleEvent("codex", "stop") {
		t.Fatal("connector event casing changed")
	}
}

func TestInvalidActionOnLifecycleEventsAllowsBothStandaloneShapes(t *testing.T) {
	for _, tc := range []struct{ connector, event string }{
		{"cursor", "stop"}, {"devin", "Stop"}, {"kiro", "Stop"},
		{"opencode", "session.idle"}, {"copilot", "agentStop"},
	} {
		for _, windowsShape := range []bool{false, true} {
			for _, body := range []string{`{}`, `{"action":"unexpected"}`} {
				sp, ok := specFor(tc.connector)
				if !ok {
					t.Fatalf("missing spec for %s", tc.connector)
				}
				var stdout, stderr bytes.Buffer
				opts := Options{Connector: tc.connector, Event: tc.event, ManagedEnterprise: true,
					FailMode: "closed", Stdout: &stdout, Stderr: &stderr}
				if windowsShape {
					opts.ExplainUnenrolledAccount = true
				} else {
					opts.ManagedStandalone = true
				}
				if code := sp.decide(opts, []byte(body)); code != 0 ||
					strings.Contains(stdout.String(), `"deny"`) || strings.Contains(stderr.String(), "failed closed") {
					t.Errorf("%s/%s Windows=%v body=%s: code=%d stdout=%q stderr=%q",
						tc.connector, tc.event, windowsShape, body, code, stdout.String(), stderr.String())
				}
				if tc.connector == "opencode" && strings.TrimSpace(stdout.String()) != `{"action":"allow"}` {
					t.Errorf("%s/%s Windows=%v: plugin did not receive an explicit allow: %q",
						tc.connector, tc.event, windowsShape, stdout.String())
				}
			}
		}
	}
}
