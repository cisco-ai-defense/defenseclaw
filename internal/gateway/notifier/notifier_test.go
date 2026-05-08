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

package notifier

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

// recorder is a synchronous test sender that captures every
// Notification the dispatcher hands off. send() is invoked from a
// goroutine inside the dispatcher, so the recorder serializes
// access on a mutex and surfaces a Drain helper that waits up to a
// short timeout for the expected count.
type recorder struct {
	mu    sync.Mutex
	items []notify.Notification
	err   error
}

func (r *recorder) Send(n notify.Notification) error {
	r.mu.Lock()
	r.items = append(r.items, n)
	err := r.err
	r.mu.Unlock()
	return err
}

func (r *recorder) Snapshot() []notify.Notification {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]notify.Notification, len(r.items))
	copy(out, r.items)
	return out
}

// Drain waits until the recorder has at least want items or
// timeout elapses, then returns the snapshot. Used to bridge the
// dispatcher's fire-and-forget goroutine into deterministic tests
// without sleeping on a fixed interval.
func (r *recorder) Drain(want int, timeout time.Duration) []notify.Notification {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got := r.Snapshot()
		if len(got) >= want {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	return r.Snapshot()
}

func enabledConfig() config.NotificationsConfig {
	c := config.DefaultNotificationsConfig()
	c.Enabled = true
	return c
}

func TestDispatcher_DisabledIsNoOp(t *testing.T) {
	rec := &recorder{}
	cfg := config.DefaultNotificationsConfig()
	cfg.Enabled = false
	d := NewWithSender(cfg, rec.Send)

	d.OnBlock(BlockEvent{Source: SourceHook, Target: "Bash", Reason: "denied"})
	d.OnWouldBlock(BlockEvent{Source: SourceHook, Target: "Bash"})
	d.OnApprovalPending(ApprovalEvent{Subject: "tool"})

	if got := rec.Drain(1, 50*time.Millisecond); len(got) != 0 {
		t.Fatalf("disabled dispatcher emitted %d notifications: %#v", len(got), got)
	}
}

func TestDispatcher_CategoryGate(t *testing.T) {
	rec := &recorder{}
	cfg := enabledConfig()
	cfg.BlockEnforced = false
	cfg.BlockWouldBlock = false
	cfg.HITLApproval = true
	d := NewWithSender(cfg, rec.Send)

	d.OnBlock(BlockEvent{Source: SourceHook, Target: "Bash", Reason: "denied"})
	d.OnWouldBlock(BlockEvent{Source: SourceHook, Target: "Bash"})
	d.OnApprovalPending(ApprovalEvent{Subject: "tool", Source: SourceHook})

	got := rec.Drain(1, 100*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("expected 1 notification (approval only), got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0].Title, "Approval needed") {
		t.Fatalf("expected approval title, got %q", got[0].Title)
	}
}

func TestDispatcher_SourceFilter(t *testing.T) {
	rec := &recorder{}
	cfg := enabledConfig()
	cfg.Sources.Hook = false
	cfg.Sources.Guardrail = true
	cfg.Sources.AssetPolicy = false
	d := NewWithSender(cfg, rec.Send)

	d.OnBlock(BlockEvent{Source: SourceHook, Target: "Bash"})
	d.OnBlock(BlockEvent{Source: SourceAssetPolicy, Target: "mcp:github"})
	d.OnBlock(BlockEvent{Source: SourceGuardrail, Target: "gpt-4o"})

	got := rec.Drain(1, 100*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("expected 1 notification (guardrail only), got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0].Title, "gpt-4o") {
		t.Fatalf("expected gpt-4o in title, got %q", got[0].Title)
	}
}

func TestDispatcher_DedupWithinWindow(t *testing.T) {
	rec := &recorder{}
	cfg := enabledConfig()
	cfg.DedupWindow = 30 * time.Second
	cfg.MaxPerMinute = 100
	d := NewWithSender(cfg, rec.Send)

	now := time.Unix(0, 0)
	d.SetClock(func() time.Time { return now })

	for i := 0; i < 5; i++ {
		d.OnBlock(BlockEvent{
			Source: SourceHook,
			Target: "Bash",
			Reason: "policy denied dangerous command",
		})
	}

	got := rec.Drain(1, 100*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("expected dedup to collapse 5 identical events to 1, got %d: %#v", len(got), got)
	}

	// Advance past the dedup window — a follow-up event must fire.
	now = now.Add(31 * time.Second)
	d.OnBlock(BlockEvent{
		Source: SourceHook,
		Target: "Bash",
		Reason: "policy denied dangerous command",
	})
	got = rec.Drain(2, 100*time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("expected 2 notifications after dedup window, got %d: %#v", len(got), got)
	}
}

func TestDispatcher_RateLimitAndRollup(t *testing.T) {
	rec := &recorder{}
	cfg := enabledConfig()
	cfg.DedupWindow = time.Millisecond // effectively no dedup
	cfg.MaxPerMinute = 3
	d := NewWithSender(cfg, rec.Send)

	now := time.Unix(0, 0)
	d.SetClock(func() time.Time { return now })

	// Each event has a unique target so dedup never kicks in. We
	// emit 6 events with a max of 3/min; expect 3 delivered + 3
	// suppressed in the first window, then a single rollup at the
	// minute boundary.
	for i := 0; i < 6; i++ {
		d.OnBlock(BlockEvent{
			Source: SourceHook,
			Target: "Tool" + string(rune('A'+i)),
			Reason: "denied",
		})
	}
	got := rec.Drain(3, 100*time.Millisecond)
	if len(got) != 3 {
		t.Fatalf("expected 3 delivered notifications under rate limit, got %d", len(got))
	}

	// Roll the minute window. The next OnBlock should emit a
	// rollup AND the new event (unique target so dedup is skipped).
	now = now.Add(61 * time.Second)
	d.OnBlock(BlockEvent{Source: SourceHook, Target: "ToolZ", Reason: "denied"})
	got = rec.Drain(5, 250*time.Millisecond)
	if len(got) < 5 {
		t.Fatalf("expected rollup + new event after window roll, got %d: %#v", len(got), got)
	}
	rollupSeen := false
	for _, n := range got {
		if strings.Contains(n.Title, "throttled") {
			rollupSeen = true
			if !strings.Contains(n.Body, "3") {
				t.Fatalf("expected rollup body to mention 3 suppressed events, got %q", n.Body)
			}
			break
		}
	}
	if !rollupSeen {
		t.Fatalf("expected rollup notification after window roll, got %#v", got)
	}
}

func TestDispatcher_SenderErrorIsSwallowed(t *testing.T) {
	rec := &recorder{err: errors.New("display server missing")}
	cfg := enabledConfig()
	d := NewWithSender(cfg, rec.Send)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("dispatcher panicked on sender error: %v", r)
		}
	}()
	d.OnBlock(BlockEvent{Source: SourceHook, Target: "Bash", Reason: "denied"})

	got := rec.Drain(1, 100*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("expected sender to be invoked once, got %d", len(got))
	}
}

func TestDispatcher_NilReceiverIsSafe(t *testing.T) {
	var d *Dispatcher
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil dispatcher panicked: %v", r)
		}
	}()
	d.OnBlock(BlockEvent{Target: "Bash"})
	d.OnWouldBlock(BlockEvent{Target: "Bash"})
	d.OnApprovalPending(ApprovalEvent{Subject: "tool"})
}

func TestBlockNotification_Subtitle(t *testing.T) {
	n := blockNotification(BlockEvent{
		Source:    SourceGuardrail,
		Target:    "gpt-4o",
		Severity:  "HIGH",
		Connector: "openclaw",
		Event:     "completion",
		Reason:    "secret found in completion",
	}, false)
	if !strings.Contains(n.Title, "blocked gpt-4o") {
		t.Fatalf("expected blocked title, got %q", n.Title)
	}
	if !strings.Contains(n.Subtitle, "guardrail") || !strings.Contains(n.Subtitle, "HIGH") {
		t.Fatalf("expected subtitle to carry source + severity, got %q", n.Subtitle)
	}
	if strings.Contains(n.Subtitle, "observe") {
		t.Fatalf("would_block=false but subtitle says observe: %q", n.Subtitle)
	}
}

func TestBlockNotification_WouldBlockTagsObserve(t *testing.T) {
	n := blockNotification(BlockEvent{
		Source:   SourceHook,
		Target:   "Bash",
		Severity: "MEDIUM",
		Reason:   "policy match",
	}, true)
	if !strings.Contains(n.Title, "would block") {
		t.Fatalf("expected 'would block' in title, got %q", n.Title)
	}
	if !strings.Contains(n.Subtitle, "observe") {
		t.Fatalf("expected observe tag in subtitle, got %q", n.Subtitle)
	}
}

func TestTruncateReason_Boundaries(t *testing.T) {
	short := "tiny reason"
	if got := truncateReason(short); got != short {
		t.Fatalf("short reason mutated: %q -> %q", short, got)
	}
	long := strings.Repeat("a", 200)
	got := truncateReason(long)
	if len(got) > 141 { // 138 chars + "..."
		t.Fatalf("truncated reason too long: %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected ellipsis suffix, got %q", got)
	}
}

// TestTruncateReason_StripsNewlines pins the contract that the toast
// body never contains literal CR / LF / TAB. The macOS osascript
// path encodes the body via json.Marshal which renders "\n" as the
// two-character escape; without normalisation the operator sees
// "regex matched\nrule:..." instead of clean text.
func TestTruncateReason_StripsNewlines(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"unix", "regex match\nrule: foo", "regex match rule: foo"},
		{"windows", "line1\r\nline2", "line1 line2"},
		{"tabs", "field1\tfield2", "field1 field2"},
		{"mixed", "a\nb\tc\rd", "a b c d"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateReason(tc.in); got != tc.want {
				t.Fatalf("truncateReason(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
