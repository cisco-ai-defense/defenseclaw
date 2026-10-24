package hookexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A per-user hook_fail_mode open is the user's choice for a confirmed
// gateway outage (owner rule, BALANCED-DEFAULTS 2026-10-23): a gateway that
// refuses the connection lets the tool call run. Every other failure is no
// outage and blocks in the same open mode: an HTTP status (5xx, 4xx, a 429
// the resends cannot outlast), a malformed, truncated or unreadable 2xx
// answer, and a gateway that took the call but did not answer in time.
func TestPerUserOpenFailModeAppliesOnlyToAConfirmedOutage(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	stall := func(_ *stubRT, req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	failures := []struct {
		name string
		rt   func() *stubRT
	}{
		{"gateway 503", func() *stubRT { return &stubRT{status: 503, body: "unavailable"} }},
		{"gateway 500 with an allow body", func() *stubRT { return &stubRT{status: 500, body: `{"action":"allow"}`} }},
		{"gateway 400", func() *stubRT { return &stubRT{status: 400, body: `{"error":"bad"}`} }},
		{"gateway 429", func() *stubRT { return &stubRT{status: 429, body: `{"error":"busy"}`} }},
		{"malformed 200", func() *stubRT { return ok(`{"action":"allow"`) }},
		{"duplicate action", func() *stubRT { return ok(`{"action":"block","action":"allow"}`) }},
		{"unreadable 200", func() *stubRT {
			return answering(http.StatusOK, &erroringBody{data: `{"action":"allow"}`, err: io.ErrUnexpectedEOF})
		}},
		{"no answer in time", func() *stubRT { return &stubRT{onRequest: stall} }},
	}
	for _, tc := range []struct{ connector, event string }{
		{"claudecode", "PreToolUse"}, {"codex", "PreToolUse"},
		{"cursor", "beforeShellExecution"}, {"copilot", "preToolUse"},
		{"devin", "PreToolUse"}, {"hermes", "pre_tool_call"},
		{"kiro", "PreToolUse"}, {"antigravity", "PreToolUse"},
	} {
		mutate := func(opts *Options) {
			opts.Event = tc.event
			opts.FailMode = "open"
			if tc.connector == "hermes" {
				opts.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo x"}}`)
			}
		}
		t.Run(tc.connector+"/gateway not running", func(t *testing.T) {
			result := run(t, tc.connector, &stubRT{err: errors.New("dial tcp 127.0.0.1:8787: connect: connection refused")}, mutate)
			if blocked(result) || !strings.Contains(result.stderr, "fail-open") {
				t.Fatalf("per-user open blocked a confirmed outage: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
		})
		for _, failure := range failures {
			t.Run(tc.connector+"/"+failure.name, func(t *testing.T) {
				result := run(t, tc.connector, failure.rt(), mutate)
				if !blocked(result) {
					t.Fatalf("per-user open allowed a %s: code=%d stdout=%q stderr=%q", failure.name, result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// The outage notice tells a Claude Code or Codex user that DefenseClaw is
// not checking the session (GAP-0377): those agents hide stderr after exit 0.
func TestPerUserOpenOutageShowsTheNoticeInTheSession(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		result := run(t, connector, &stubRT{err: errors.New("dial tcp: connection refused")}, nil)
		if result.code != 0 || !strings.Contains(result.stdout, `"systemMessage"`) ||
			!strings.Contains(result.stdout, "defenseclaw-gateway start") {
			t.Fatalf("%s: code=%d stdout=%q, want the outage systemMessage", connector, result.code, result.stdout)
		}
	}
}

// A registration that lost its event and Hermes input whose event fields
// disagree are no outage: a per-user open hook refuses them too.
func TestPerUserOpenHookRefusesBrokenBindingsAndAmbiguousEvents(t *testing.T) {
	copilot := run(t, "copilot", ok(`{"action":"allow"}`), func(opts *Options) { opts.Event = "futureEvent" })
	if !strings.Contains(copilot.stdout, `"permissionDecision":"deny"`) || copilot.rt.requests != 0 {
		t.Fatalf("copilot unbound: stdout=%q requests=%d, want a deny without a gateway call", copilot.stdout, copilot.rt.requests)
	}
	antigravity := run(t, "antigravity", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.Event = ""
		opts.Stdin = strings.NewReader(`{"toolCall":{"name":"run_command","args":{"CommandLine":"echo x"}}}`)
	})
	if !strings.Contains(antigravity.stdout, `"decision":"deny"`) {
		t.Fatalf("antigravity unbound: stdout=%q, want a deny", antigravity.stdout)
	}
	hermes := run(t, "hermes", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.Event = ""
		opts.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","event":"pre_llm_call","tool_name":"terminal","tool_input":{"command":"echo x"}}`)
	})
	if !blocked(hermes) || hermes.rt.requests != 0 {
		t.Fatalf("hermes conflicting events: code=%d stdout=%q requests=%d, want a block", hermes.code, hermes.stdout, hermes.rt.requests)
	}
}

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
		{"antigravity", "PreToolUse", `{"decision":"allow"}`},
		{"cursor", "beforeShellExecution", `{"permission":"allow"}`},
		{"copilot", "preToolUse", `{"permissionDecision":"allow"}`},
		{"devin", "PreToolUse", `{"decision":"allow"}`},
		{"kiro", "PreToolUse", `{"decision":"allow"}`},
		{"opencode", "tool.execute.before", `{"decision":"allow"}`},
	} {
		for _, managed := range []bool{false, true} {
			for _, failMode := range []string{"closed", "open"} {
				t.Run(tc.connector+"/"+map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+failMode, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					opts := Options{Connector: tc.connector, Event: tc.event, FailMode: failMode, ManagedEnterprise: managed, ManagedStandalone: managed, Stdout: &stdout, Stderr: &stderr}
					body := `{"action":"block","hook_output":` + tc.output + `}`
					code := specs[tc.connector].decide(opts, []byte(body))
					if code == 0 && !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), "block") {
						t.Fatalf("contradictory native output allowed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
					}
				})
			}
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
