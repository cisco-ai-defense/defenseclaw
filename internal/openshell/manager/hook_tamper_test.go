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

package manager

import (
	"testing"
	"time"
)

func TestHookTamperTracker_PostToolUseWithoutPre(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"
	toolUseID := "tool-1"

	// PostToolUse without PreToolUse should detect tamper.
	tampered, reason := tracker.CheckPostToolUse(bindingID, toolUseID, "PostToolUse")
	if !tampered {
		t.Fatal("expected tamper detection for PostToolUse without PreToolUse")
	}
	if reason == "" {
		t.Fatal("expected non-empty tamper reason")
	}
}

func TestHookTamperTracker_PostToolUseAfterDeniedPre(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"
	toolUseID := "tool-1"

	// Record a denied PreToolUse.
	tracker.ObservePreToolUse(bindingID, toolUseID, "bash", "PreToolUse", true)

	// PostToolUse for a denied PreToolUse should detect tamper.
	tampered, reason := tracker.CheckPostToolUse(bindingID, toolUseID, "PostToolUse")
	if !tampered {
		t.Fatal("expected tamper detection for PostToolUse after denied PreToolUse")
	}
	if reason == "" {
		t.Fatal("expected non-empty tamper reason")
	}
}

func TestHookTamperTracker_PostToolUseAfterAllowedPre(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"
	toolUseID := "tool-1"

	// Record an allowed PreToolUse.
	tracker.ObservePreToolUse(bindingID, toolUseID, "bash", "PreToolUse", false)

	// PostToolUse for an allowed PreToolUse should NOT detect tamper.
	tampered, reason := tracker.CheckPostToolUse(bindingID, toolUseID, "PostToolUse")
	if tampered {
		t.Fatalf("unexpected tamper detection for valid tool call: %s", reason)
	}
}

func TestHookTamperTracker_EmptyToolUseID(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"

	// Empty tool_use_id should be ignored.
	tracker.ObservePreToolUse(bindingID, "", "bash", "PreToolUse", false)
	tampered, _ := tracker.CheckPostToolUse(bindingID, "", "PostToolUse")
	if tampered {
		t.Fatal("expected no tamper detection for empty tool_use_id")
	}
}

func TestHookTamperTracker_BoundedMemory(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"

	// Add more than maxTrackedToolCalls.
	for i := 0; i < maxTrackedToolCalls+10; i++ {
		toolUseID := "tool-" + string(rune(i))
		tracker.ObservePreToolUse(bindingID, toolUseID, "bash", "PreToolUse", false)
	}

	// Check that we don't exceed the limit.
	if btc := tracker.bindings[bindingID]; btc != nil {
		if len(btc.pending) > maxTrackedToolCalls {
			t.Fatalf("tracker exceeded max: got %d, want <= %d", len(btc.pending), maxTrackedToolCalls)
		}
	}
}

func TestHookTamperTracker_Cleanup(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"
	now := time.Now()

	// Add a tool call that should be cleaned up.
	tracker.ObservePreToolUse(bindingID, "old-tool", "bash", "PreToolUse", false)

	// Manually set the insertedAt to make it stale.
	if btc := tracker.bindings[bindingID]; btc != nil {
		if rec, ok := btc.pending["old-tool"]; ok {
			rec.insertedAt = now.Add(-toolCallTTL - time.Minute)
			btc.pending["old-tool"] = rec
		}
	}

	// Run cleanup.
	tracker.Cleanup(now)

	// Verify the stale entry was removed.
	if btc := tracker.bindings[bindingID]; btc != nil {
		if _, ok := btc.pending["old-tool"]; ok {
			t.Fatal("expected stale tool call to be cleaned up")
		}
	}
}

func TestHookTamperTracker_ForgetBinding(t *testing.T) {
	tracker := newHookTamperTracker()
	bindingID := "test-binding"
	toolUseID := "tool-1"

	tracker.ObservePreToolUse(bindingID, toolUseID, "bash", "PreToolUse", false)

	// Forget the binding.
	tracker.ForgetBinding(bindingID)

	// Verify the binding state was removed.
	if btc := tracker.bindings[bindingID]; btc != nil {
		t.Fatal("expected binding to be forgotten")
	}
}

func TestIsPreToolUseEvent(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"PreToolUse", true},
		{"preToolUse", true},
		{"pre_tool_use", true},
		{"pre-tool-use", true},
		{"beforeToolUse", true},
		{"BeforeToolUse", true},
		{"PostToolUse", false},
		{"SessionStart", false},
		{"tool.call", true},
		{"toolCall", true},
	}
	for _, tt := range tests {
		got := isPreToolUseEvent(tt.event)
		if got != tt.want {
			t.Errorf("isPreToolUseEvent(%q) = %v, want %v", tt.event, got, tt.want)
		}
	}
}

func TestIsPostToolUseEvent(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"PostToolUse", true},
		{"postToolUse", true},
		{"post_tool_use", true},
		{"post-tool-use", true},
		{"afterToolUse", true},
		{"AfterToolUse", true},
		{"PreToolUse", false},
		{"SessionStart", false},
		{"tool.result", true},
		{"toolResult", true},
	}
	for _, tt := range tests {
		got := isPostToolUseEvent(tt.event)
		if got != tt.want {
			t.Errorf("isPostToolUseEvent(%q) = %v, want %v", tt.event, got, tt.want)
		}
	}
}
