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

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// routerTestInspector records calls for testing.
type routerTestInspector struct {
	calls     []routerTestCall
	verdict   *ScanVerdict
	modeTrack string
}

type routerTestCall struct {
	Direction string
	Content   string
	Model     string
	Mode      string
}

func (m *routerTestInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, model, mode string) *ScanVerdict {
	m.calls = append(m.calls, routerTestCall{direction, content, model, mode})
	if m.verdict != nil {
		return m.verdict
	}
	return allowVerdict("mock")
}

func (m *routerTestInspector) SetScannerMode(mode string) {
	m.modeTrack = mode
}

func TestEventRouter_InspectOutboundMessage(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)

	mock := &routerTestInspector{
		verdict: &ScanVerdict{
			Action:   "alert",
			Severity: "MEDIUM",
			Reason:   "test-pii",
			Findings: []string{"JUDGE-PII-EMAIL"},
		},
	}
	r.SetInspector(mock)

	r.inspectOutboundMessage("session-1", "email: user@example.com", "gpt-4")

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 inspect call, got %d", len(mock.calls))
	}
	call := mock.calls[0]
	if call.Direction != "completion" {
		t.Errorf("expected direction=completion, got %q", call.Direction)
	}
	if call.Mode != "observe" {
		t.Errorf("expected default mode=observe, got %q", call.Mode)
	}
}

func TestEventRouter_InspectOutboundMessage_EnforceMode(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)
	r.SetGuardrailMode("enforce")

	mock := &routerTestInspector{}
	r.SetInspector(mock)

	r.inspectOutboundMessage("session-1", "test content", "gpt-4")

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 inspect call, got %d", len(mock.calls))
	}
	if mock.calls[0].Mode != "enforce" {
		t.Errorf("expected mode=enforce, got %q", mock.calls[0].Mode)
	}
}

func TestEventRouter_InspectOutboundMessage_NilInspector(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)
	// No inspector set — should not panic.
	r.inspectOutboundMessage("session-1", "test content", "gpt-4")
}

func TestEventRouter_ContextTrackerIntegration(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)

	if r.contextTracker == nil {
		t.Fatal("expected contextTracker to be initialized")
	}

	r.contextTracker.Record("s1", "user", "hello")
	r.contextTracker.Record("s1", "assistant", "hi")

	msgs := r.contextTracker.RecentMessages("s1", 10)
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}
}

func TestEventRouter_OutboundWithContextTracker(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)

	r.contextTracker.Record("s1", "user", "Tell me about Go")
	r.contextTracker.Record("s1", "assistant", "Go is a programming language...")

	mock := &routerTestInspector{}
	r.SetInspector(mock)

	r.inspectOutboundMessage("s1", "Here is the answer", "gpt-4")

	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
}

func TestEventRouter_InspectToolOutput(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)

	rp := LoadRulePack("")
	r.SetRulePack(rp)

	// Should not panic with a tool that has no sensitive config.
	r.inspectToolOutput("some-unknown-tool", "normal output")

	// Use a tool name that is actually in sensitive-tools.yaml with ResultInspection=true.
	// "users_list" is defined in the default sensitive tools config.
	st := rp.GetSensitiveTool("users_list")
	if st == nil {
		t.Log("users_list not in sensitive tools, adding for test")
		rp.SensitiveTools["users_list"] = &SensitiveToolYAML{
			Name:             "users_list",
			ResultInspection: true,
		}
	}

	// Content with a secret — this should now actually hit the scanning path.
	r.inspectToolOutput("users_list", "AKIAIOSFODNN7EXAMPLE is an AWS access key")
}

func TestEventRouter_InspectToolOutput_NoRulePack(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger := audit.NewLogger(store)

	r := NewEventRouter(nil, store, logger, false, nil)
	// No rule pack set — should return early without panic.
	r.inspectToolOutput("users_list", "AKIAIOSFODNN7EXAMPLE")
}
