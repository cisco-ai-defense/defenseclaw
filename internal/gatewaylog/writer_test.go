// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriter_JSONLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	w, err := New(Config{JSONLPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w.Emit(Event{
		EventType: EventVerdict,
		Severity:  SeverityHigh,
		Provider:  "amazon-bedrock",
		Model:     "anthropic.claude-3-5-sonnet",
		Direction: DirectionPrompt,
		RequestID: "req-1",
		Verdict: &VerdictPayload{
			Stage:      StageRegex,
			Action:     "block",
			Reason:     "pii.email detected",
			Categories: []string{"pii.email"},
			LatencyMs:  3,
		},
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(lines), string(data))
	}

	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v\nline=%q", err, lines[0])
	}
	if got.EventType != EventVerdict {
		t.Fatalf("event_type: got %q want %q", got.EventType, EventVerdict)
	}
	if got.Verdict == nil || got.Verdict.Action != "block" {
		t.Fatalf("verdict payload lost: %+v", got.Verdict)
	}
}

func TestWriter_PrettyFormat(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(Config{Pretty: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w.Emit(Event{
		EventType: EventJudge,
		Severity:  SeverityMedium,
		Direction: DirectionPrompt,
		Judge: &JudgePayload{
			Kind:       "injection",
			Model:      "claude-3-5-sonnet",
			InputBytes: 512,
			LatencyMs:  420,
			Action:     "warn",
			Severity:   SeverityMedium,
		},
	})

	out := buf.String()
	for _, want := range []string{"[judge:injection]", "action=warn", "in=512B", "lat=420ms"} {
		if !strings.Contains(out, want) {
			t.Fatalf("pretty output missing %q:\n%s", want, out)
		}
	}
}

func TestWriter_FanoutInvoked(t *testing.T) {
	w, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var seen []Event
	w.WithFanout(func(e Event) { seen = append(seen, e) })
	w.Emit(Event{EventType: EventLifecycle, Lifecycle: &LifecyclePayload{Subsystem: "gateway", Transition: "start"}})

	if len(seen) != 1 || seen[0].EventType != EventLifecycle {
		t.Fatalf("fanout not invoked correctly: %+v", seen)
	}
}

func TestWriter_EmitAfterCloseIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	w, err := New(Config{JSONLPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// must not panic or resurrect the file handle
	w.Emit(Event{EventType: EventLifecycle, Lifecycle: &LifecyclePayload{Subsystem: "gateway", Transition: "stop"}})
	if err := w.Close(); err != nil {
		t.Fatalf("double-Close: %v", err)
	}
}
