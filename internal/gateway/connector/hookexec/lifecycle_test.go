// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
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
	// Compare the whole map, so a new connector key fails here as well as a
	// new or dropped event of a listed connector.
	if !reflect.DeepEqual(neutralLifecycleSets, want) {
		t.Fatalf("lifecycle sets = %v, want %v", neutralLifecycleSets, want)
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
		{"amp", "Stop"}, {"hermes", "on_session_end"}, {"", "Stop"},
	} {
		if NeutralLifecycleEvent(tc.connector, tc.event) {
			t.Errorf("%s/%s unexpectedly neutral", tc.connector, tc.event)
		}
	}
	if !NeutralLifecycleEvent("cursor", "SESSIONEND") || NeutralLifecycleEvent("codex", "stop") {
		t.Fatal("connector event casing changed")
	}
}

// LifecycleEvent adds the looping stop events to the neutral set and nothing
// else: Antigravity's Stop veto re-enters the agent loop, its tool events stay
// enforcement events.
func TestLifecycleEventAddsLoopingStopEvents(t *testing.T) {
	if !reflect.DeepEqual(loopingStopEvents, map[string][]string{"antigravity": {"Stop"}}) {
		t.Fatalf("looping stop events = %v", loopingStopEvents)
	}
	for connector, events := range neutralLifecycleSets {
		if got := LifecycleEvents(connector); !reflect.DeepEqual(got, events) {
			t.Errorf("%s lifecycle events = %v, want the neutral set %v", connector, got, events)
		}
		for _, event := range events {
			if !LifecycleEvent(connector, event) {
				t.Errorf("%s/%s missing from LifecycleEvent", connector, event)
			}
		}
	}
	if got := LifecycleEvents("antigravity"); !reflect.DeepEqual(got, []string{"Stop"}) {
		t.Errorf("antigravity lifecycle events = %v", got)
	}
	if !LifecycleEvent("antigravity", "Stop") || NeutralLifecycleEvent("antigravity", "Stop") {
		t.Error("antigravity Stop must be a lifecycle event outside the neutral runner set")
	}
	for _, tc := range []struct{ connector, event string }{
		{"antigravity", "PreToolUse"}, {"antigravity", "PostToolUse"}, {"antigravity", "stop"},
		{"claudecode", "PostToolBatch"}, {"claudecode", "PreToolUse"}, {"codex", "PreToolUse"},
		{"amp", "agent.end"}, {"hermes", "on_session_end"},
	} {
		if LifecycleEvent(tc.connector, tc.event) {
			t.Errorf("%s/%s unexpectedly a lifecycle event", tc.connector, tc.event)
		}
	}
}

// TestInvalidActionOnLifecycleEventsAllowsBothStandaloneShapes covers every
// lifecycle event, Claude Code and Codex included, on the Unix standalone and
// the Windows standalone shapes: a missing or unknown action is a neutral
// allow there, never a block, a deny or a follow-up.
func TestInvalidActionOnLifecycleEventsAllowsBothStandaloneShapes(t *testing.T) {
	for connector, events := range neutralLifecycleSets {
		sp, ok := specFor(connector)
		if !ok {
			t.Fatalf("missing spec for %s", connector)
		}
		for _, event := range events {
			for _, windowsShape := range []bool{false, true} {
				for _, body := range []string{`{}`, `{"action":"unexpected"}`} {
					var stdout, stderr bytes.Buffer
					opts := Options{Connector: connector, Event: event, ManagedEnterprise: true,
						FailMode: "closed", Stdout: &stdout, Stderr: &stderr}
					if windowsShape {
						opts.ExplainUnenrolledAccount = true
					} else {
						opts.ManagedStandalone = true
					}
					code := sp.decide(opts, []byte(body))
					out := stdout.String()
					if code != 0 || strings.Contains(out, `"deny"`) || strings.Contains(out, `"block"`) ||
						strings.Contains(out, "followup_message") || strings.Contains(stderr.String(), "failed closed") {
						t.Errorf("%s/%s Windows=%v body=%s: code=%d stdout=%q stderr=%q",
							connector, event, windowsShape, body, code, out, stderr.String())
					}
					if connector == "opencode" && strings.TrimSpace(out) != `{"action":"allow"}` {
						t.Errorf("%s/%s Windows=%v: plugin did not receive an explicit allow: %q",
							connector, event, windowsShape, out)
					}
				}
			}
		}
	}
}

// The Secure Client bytes remain pinned to the historical golden. Other
// profiles keep lifecycle events neutral when a gateway action is unusable.
func TestInvalidActionOnLifecycleEventsKeepsPerUserAndSecureClientBytes(t *testing.T) {
	f, err := os.Open("testdata/lifecycle_invalid_action_6210dbcee.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type row struct {
		Connector, Event, Profile, Body, Stdout, Stderr string
		Code                                            int
	}
	covered := map[[3]string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var want row
		if err := json.Unmarshal(scanner.Bytes(), &want); err != nil {
			t.Fatalf("golden row %q: %v", scanner.Text(), err)
		}
		sp, ok := specFor(want.Connector)
		if !ok {
			t.Fatalf("missing spec for %s", want.Connector)
		}
		var stdout, stderr bytes.Buffer
		opts := Options{Connector: want.Connector, Event: want.Event, Stdout: &stdout, Stderr: &stderr}
		switch want.Profile {
		case "oss-closed":
			opts.FailMode = "closed"
		case "oss-open":
			opts.FailMode = "open"
		case "secure-client":
			opts.ManagedEnterprise, opts.SecureClient, opts.FailMode = true, true, "closed"
		default:
			t.Fatalf("unknown golden profile %q", want.Profile)
		}
		code := sp.decide(opts, []byte(want.Body))
		if want.Profile != "secure-client" {
			if code != 0 || strings.Contains(stdout.String(), `"deny"`) || strings.Contains(stdout.String(), `"block"`) {
				t.Errorf("%s/%s %s body=%s: lifecycle event not neutral: code=%d stdout=%q stderr=%q",
					want.Connector, want.Event, want.Profile, want.Body, code, stdout.String(), stderr.String())
			}
			covered[[3]string{want.Connector, want.Event, want.Profile}]++
			continue
		}
		gotStderr := stderr.String()
		if code != want.Code || stdout.String() != want.Stdout || gotStderr != want.Stderr {
			t.Errorf("%s/%s %s body=%s:\n got code=%d stdout=%q stderr=%q\nwant code=%d stdout=%q stderr=%q",
				want.Connector, want.Event, want.Profile, want.Body,
				code, stdout.String(), gotStderr, want.Code, want.Stdout, want.Stderr)
		}
		covered[[3]string{want.Connector, want.Event, want.Profile}]++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for connector, events := range neutralLifecycleSets {
		for _, event := range events {
			for _, profile := range []string{"oss-closed", "oss-open", "secure-client"} {
				if covered[[3]string{connector, event, profile}] != 2 {
					t.Errorf("%s/%s %s: golden rows = %d, want 2 (missing and unknown action)",
						connector, event, profile, covered[[3]string{connector, event, profile}])
				}
			}
		}
	}
}
