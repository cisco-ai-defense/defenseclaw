// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func trackerReport(id, fields string) Message {
	return Message{JSONRPC: "2.0", Method: "session/update", Params: json.RawMessage(
		`{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"` + id + `"` + fields + `}}`)}
}

func trackerPermission(id string) Message {
	return Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "session/request_permission", Params: json.RawMessage(
		`{"sessionId":"s","toolCall":{"toolCallId":"` + id + `"},"options":[]}`)}
}

// A state over the bound keeps its first locations, at most
// MaxToolCallLocations, and says it was cut: what was seen first is still
// judged (ACP review round 4, P3-2).
func TestToolCallTrackerKeepsTheFirstLocationsOfAnOversizedState(t *testing.T) {
	locations := func(count int) string {
		var list []string
		for i := 0; i < count; i++ {
			list = append(list, fmt.Sprintf(`{"path":"/work/src/pkg%04d/file_with_a_long_name_%04d.go"}`, i, i))
		}
		return "[" + strings.Join(list, ",") + "]"
	}
	for _, tc := range []struct {
		name, fields string
		want         int
	}{
		{"locations alone", `,"kind":"edit","locations":` + locations(1201), MaxToolCallLocations},
		{"with a large input", `,"kind":"edit","rawInput":{"content":"` + strings.Repeat("a", MaxToolCallStateBytes) + `"},"locations":` + locations(1201), MaxToolCallLocations},
		{"within the bound", `,"kind":"edit","locations":` + locations(70), 70},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tracker ToolCallTracker
			tracker.Commit(trackerReport("t", tc.fields), false)
			state := tracker.Peek(trackerPermission("t"))
			if len(state) > MaxToolCallStateBytes {
				t.Fatalf("state of %d bytes, over the bound", len(state))
			}
			var got struct {
				Kind      string
				Truncated bool
				Locations []struct{ Path string }
			}
			if err := json.Unmarshal(state, &got); err != nil {
				t.Fatal(err)
			}
			if got.Kind != "edit" || len(got.Locations) != tc.want || got.Truncated != (tc.want != 70) {
				t.Fatalf("kind %q, %d locations, truncated %v; want %d locations", got.Kind, len(got.Locations), got.Truncated, tc.want)
			}
			if got.Locations[0].Path != "/work/src/pkg0000/file_with_a_long_name_0000.go" {
				t.Fatalf("the first location kept is %q", got.Locations[0].Path)
			}
		})
	}
	// Locations that do not fit at all are left out, and the state still says so.
	var tracker ToolCallTracker
	tracker.Commit(trackerReport("t", `,"kind":"edit","locations":[{"path":"/`+strings.Repeat("p", MaxToolCallStateBytes)+`"}]`), false)
	var got toolCallFields
	if err := json.Unmarshal(tracker.Peek(trackerPermission("t")), &got); err != nil || !got.Truncated || len(got.Locations) != 0 || string(got.Kind) != `"edit"` {
		t.Fatalf("a location larger than the bound: %s", tracker.Peek(trackerPermission("t")))
	}
}

// A report the gateway judged a block stays marked for as long as the guard
// knows the call: through later updates, a repeated first report, and the drop
// of its state (ACP review round 4, P3-1).
func TestToolCallTrackerKeepsTheReportBlockMark(t *testing.T) {
	var tracker ToolCallTracker
	flagged := func(id string) bool {
		var got toolCallFields
		return json.Unmarshal(tracker.Peek(trackerPermission(id)), &got) == nil && got.Flagged
	}
	tracker.Commit(trackerReport("t", `,"kind":"execute","rawInput":{"command":"x"}`), true)
	tracker.Commit(trackerReport("clean", `,"kind":"execute","rawInput":{"command":"ls"}`), false)
	update := Message{JSONRPC: "2.0", Method: "session/update", Params: json.RawMessage(
		`{"sessionId":"s","update":{"sessionUpdate":"tool_call_update","toolCallId":"t","status":"in_progress"}}`)}
	tracker.Commit(update, false)
	tracker.Commit(trackerReport("t", `,"title":"again"`), false)
	if !flagged("t") || flagged("clean") {
		t.Fatalf("marks: t %v, clean %v", flagged("t"), flagged("clean"))
	}
	for i := 0; i < MaxTrackedToolCalls; i++ {
		tracker.Commit(trackerReport(fmt.Sprintf("o%d", i), `,"kind":"read"`), false)
	}
	if got := string(tracker.Peek(trackerPermission("t"))); got != `{"dropped":true,"flagged":true}` {
		t.Fatalf("a dropped call whose report was judged a block: %s", got)
	}
	if got := string(tracker.Peek(trackerPermission("clean"))); got != `{"dropped":true}` {
		t.Fatalf("a dropped call: %s", got)
	}
	// Reported again after its drop, it keeps the mark.
	tracker.Commit(trackerReport("t", `,"kind":"read"`), false)
	if !flagged("t") {
		t.Fatalf("a call reported again after its drop lost the mark: %s", tracker.Peek(trackerPermission("t")))
	}
}

// End to end through the guard: the report's verdict is kept with the call
// and reaches the gateway with the permission.
func TestCopyFramesMarksAReportTheGatewayJudgedABlock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict Verdict
		want    bool
	}{
		{"a report allowed as an alert that would have blocked", Verdict{Action: "alert", RawAction: "block", WouldBlock: true}, true},
		{"an observe-mode would-block", Verdict{Action: "allow", RawAction: "block", WouldBlock: true}, true},
		{"an alert", Verdict{Action: "alert", RawAction: "alert"}, false},
		{"an allow", Verdict{Action: "allow"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := &scriptedEvaluator{answer: func(in Evaluation) (Verdict, error) {
				if in.Method == "session/update" {
					return tc.verdict, nil
				}
				return Verdict{Action: "allow"}, nil
			}}
			state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
			opts := ProxyOptions{Mode: ModeAction, Evaluator: evaluator, Stderr: io.Discard}
			frames := `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"t","kind":"execute","rawInput":{"command":"x"}}}}` + "\n" +
				`{"jsonrpc":"2.0","id":7,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"t"},"options":[]}}` + "\n"
			if err := copyFrames(context.Background(), opts, state, AgentToClient, strings.NewReader(frames), io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			var got toolCallFields
			if len(evaluator.seen) != 2 || json.Unmarshal(evaluator.seen[1].ToolCallState, &got) != nil || got.Flagged != tc.want {
				t.Fatalf("the permission reached the gateway with state %s, want flagged %v", evaluator.seen[len(evaluator.seen)-1].ToolCallState, tc.want)
			}
		})
	}
}

// scriptedEvaluator answers each evaluation with answer and records it.
type scriptedEvaluator struct {
	seen   []Evaluation
	answer func(Evaluation) (Verdict, error)
}

func (e *scriptedEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	e.seen = append(e.seen, in)
	return e.answer(in)
}

// The guard leaves session_cwd and tool_call_state out only after the gateway
// refused them and then judged the frame without them, and sends them again
// after the gateway did not answer: the one that answers next may be newer
// (ACP review round 4, P4-1).
func TestCopyFramesTurnsTheContextFieldsOffOnlyAfterTheRetryWorks(t *testing.T) {
	frameID := func(in Evaluation) string {
		var frame struct{ ID json.RawMessage }
		_ = json.Unmarshal(in.Payload, &frame)
		return string(frame.ID)
	}
	refused := &GatewayRefusedError{Status: 400, Message: "invalid ACP evaluation body"}
	evaluator := &scriptedEvaluator{answer: func(in Evaluation) (Verdict, error) {
		switch frameID(in) {
		case "1": // refused with the fields and without them
			return Verdict{}, refused
		case "2": // a gateway that predates the fields
			if in.SessionCWD != "" {
				return Verdict{}, refused
			}
		case "3": // the gateway stopped
			return Verdict{}, errors.New("connection refused")
		}
		return Verdict{Action: "allow"}, nil // 4: a newer gateway
	}}
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
	opts := ProxyOptions{Mode: ModeAction, Evaluator: evaluator, Stderr: io.Discard}
	if err := copyFrames(context.Background(), opts, state, ClientToAgent,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"session/load","params":{"sessionId":"s","cwd":"/tmp/x"}}`+"\n"), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var frames strings.Builder
	for id := 1; id <= 4; id++ {
		fmt.Fprintf(&frames, `{"jsonrpc":"2.0","id":%d,"method":"terminal/create","params":{"sessionId":"s","command":"echo ok"}}`+"\n", id)
	}
	if err := copyFrames(context.Background(), opts, state, AgentToClient, strings.NewReader(frames.String()), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	first := map[string]bool{} // whether the first evaluation of each frame held the field
	for _, seen := range evaluator.seen {
		if id := frameID(seen); seen.Method == "terminal/create" {
			if _, ok := first[id]; !ok {
				first[id] = seen.SessionCWD != ""
			}
		}
	}
	if want := map[string]bool{"1": true, "2": true, "3": false, "4": true}; fmt.Sprint(first) != fmt.Sprint(want) {
		t.Fatalf("first evaluation of each frame held session_cwd: %v, want %v", first, want)
	}
	if state.gatewayIgnoresContext() {
		t.Fatal("the fields are still off after a gateway that knows them answered")
	}
}
