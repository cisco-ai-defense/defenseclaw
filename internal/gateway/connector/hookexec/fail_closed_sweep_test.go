package hookexec

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestInvalidNativeActionFailsClosed(t *testing.T) {
	for _, tc := range []struct{ connector, event string }{
		{"cursor", "beforeShellExecution"}, {"copilot", "preToolUse"},
		{"devin", "PreToolUse"}, {"kiro", "PreToolUse"},
		{"opencode", "tool.execute.before"},
	} {
		for _, body := range []string{`{}`, `{"action":"unrecognized"}`} {
			t.Run(tc.connector+"/"+body, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				opts := Options{Connector: tc.connector, Event: tc.event, FailMode: "closed", Stdout: &stdout, Stderr: &stderr}
				code := specs[tc.connector].decide(opts, []byte(body))
				if code == 0 && !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), "block") {
					t.Fatalf("unusable gateway action allowed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestContradictoryNativeBlockFailsClosed(t *testing.T) {
	for _, tc := range []struct{ connector, event, output string }{
		{"cursor", "beforeShellExecution", `{"permission":"allow"}`},
		{"copilot", "preToolUse", `{"permissionDecision":"allow"}`},
		{"devin", "PreToolUse", `{"decision":"allow"}`},
		{"kiro", "PreToolUse", `{"decision":"allow"}`},
	} {
		for _, managed := range []bool{false, true} {
			t.Run(tc.connector+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				opts := Options{Connector: tc.connector, Event: tc.event, FailMode: "closed", ManagedEnterprise: managed, ManagedStandalone: managed, Stdout: &stdout, Stderr: &stderr}
				body := `{"action":"block","hook_output":` + tc.output + `}`
				code := specs[tc.connector].decide(opts, []byte(body))
				if code == 0 && !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), "block") {
					t.Fatalf("contradictory native output allowed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestPerUserClosedMissingHomeFailsClosed(t *testing.T) {
	for _, tc := range []struct{ connector, event, payload string }{
		{"claudecode", "PreToolUse", `{"hook_event_name":"PreToolUse"}`},
		{"copilot", "preToolUse", `{}`},
		{"hermes", "pre_tool_call", `{"event":"pre_tool_call"}`},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opts := Options{Connector: tc.connector, Event: tc.event, FailMode: "closed", Home: t.TempDir() + "/missing", Stdin: strings.NewReader(tc.payload), Stdout: &stdout, Stderr: &stderr}
			code := Run(context.Background(), opts)
			if code == 0 && !strings.Contains(stdout.String(), "block") && !strings.Contains(stdout.String(), "deny") {
				t.Fatalf("missing home allowed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
