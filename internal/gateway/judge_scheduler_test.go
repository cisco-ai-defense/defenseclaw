// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

func mustAcquire(t *testing.T, s *judgeScheduler, class judgeCallClass) func() {
	t.Helper()
	release, err := s.acquire(context.Background(), class)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	return release
}

// acquireAsync starts an acquire and reports on the returned channel once it
// holds a slot (or failed).
func acquireAsync(ctx context.Context, s *judgeScheduler, class judgeCallClass) <-chan func() {
	got := make(chan func(), 1)
	go func() {
		release, err := s.acquire(ctx, class)
		if err != nil {
			got <- nil
			return
		}
		got <- release
	}()
	return got
}

func waitQueued(t *testing.T, s *judgeScheduler, class judgeCallClass, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.queued(class) != n {
		if time.Now().After(deadline) {
			t.Fatalf("queued(%d) = %d, want %d", class, s.queued(class), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestJudgeSchedulerNilAndZeroLimitNeverWait(t *testing.T) {
	var none *judgeScheduler
	release, err := none.acquire(context.Background(), judgeCallContent)
	if err != nil {
		t.Fatalf("nil scheduler: %v", err)
	}
	release()
	s := &judgeScheduler{}
	for i := 0; i < 50; i++ {
		mustAcquire(t, s, judgeCallContent)
	}
	if judgeSchedulerFor("http://127.0.0.1:1/unset-1395", 0) != nil {
		t.Fatal("max_parallel 0 made a scheduler; want none (no limit)")
	}
}

// With one slot, a tool call that arrives after queued prompt checks gets the
// slot first (#1395).
func TestJudgeSchedulerToolCallGoesAheadOfQueuedPromptChecks(t *testing.T) {
	s := &judgeScheduler{limit: 1}
	inFlight := mustAcquire(t, s, judgeCallContent)
	prompt1 := acquireAsync(context.Background(), s, judgeCallContent)
	prompt2 := acquireAsync(context.Background(), s, judgeCallContent)
	waitQueued(t, s, judgeCallContent, 2)
	tool := acquireAsync(context.Background(), s, judgeCallTool)
	waitQueued(t, s, judgeCallTool, 1)

	inFlight()
	select {
	case release := <-tool:
		if release == nil {
			t.Fatal("tool acquire failed")
		}
		select {
		case <-prompt1:
			t.Fatal("a prompt check started while the tool call held the only slot")
		case <-prompt2:
			t.Fatal("a prompt check started while the tool call held the only slot")
		case <-time.After(20 * time.Millisecond):
		}
		release()
	case <-prompt1:
		t.Fatal("the queued prompt check got the slot before the tool call")
	case <-time.After(2 * time.Second):
		t.Fatal("the tool call never got the slot")
	}
	// The two prompt checks then run one at a time, in either order.
	for pending := []<-chan func(){prompt1, prompt2}; len(pending) > 0; {
		select {
		case release := <-pending[0]:
			release()
			pending = pending[1:]
		case release := <-pending[len(pending)-1]:
			release()
			pending = pending[:len(pending)-1]
		case <-time.After(2 * time.Second):
			t.Fatal("a queued prompt check never ran")
		}
	}
}

// With two or more slots, prompt checks never hold the last one, so a tool
// call starts at once.
func TestJudgeSchedulerKeepsOneSlotForToolCalls(t *testing.T) {
	s := &judgeScheduler{limit: 2}
	prompt := mustAcquire(t, s, judgeCallContent)
	second := acquireAsync(context.Background(), s, judgeCallContent)
	waitQueued(t, s, judgeCallContent, 1)
	start := time.Now()
	tool := mustAcquire(t, s, judgeCallTool)
	if waited := time.Since(start); waited > 100*time.Millisecond {
		t.Fatalf("tool call waited %s with a prompt check in flight, want the kept slot", waited)
	}
	tool()
	prompt()
	(<-second)()
}

// A call that waits past its deadline leaves the queue and returns its
// context error; the calls behind it still run.
func TestJudgeSchedulerWaitCountsAgainstTheCallDeadline(t *testing.T) {
	s := &judgeScheduler{limit: 1}
	held := mustAcquire(t, s, judgeCallContent)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := s.acquire(ctx, judgeCallTool); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire past deadline: %v, want DeadlineExceeded", err)
	}
	if s.queued(judgeCallTool) != 0 {
		t.Fatal("the expired tool call is still queued")
	}
	next := acquireAsync(context.Background(), s, judgeCallContent)
	waitQueued(t, s, judgeCallContent, 1)
	held()
	select {
	case release := <-next:
		release()
	case <-time.After(2 * time.Second):
		t.Fatal("the content call behind the expired tool call never ran")
	}
}

func TestJudgeSchedulerReleaseIsIdempotentAndLimitChangesApply(t *testing.T) {
	s := &judgeScheduler{limit: 1}
	held := mustAcquire(t, s, judgeCallTool)
	waiter := acquireAsync(context.Background(), s, judgeCallContent)
	waitQueued(t, s, judgeCallContent, 1)
	s.setLimit(0) // a reload that removes max_parallel starts every waiting call
	select {
	case release := <-waiter:
		release()
	case <-time.After(2 * time.Second):
		t.Fatal("removing the limit did not start the waiting call")
	}
	held()
	held()
	if s.running != 0 || s.runningContent != 0 {
		t.Fatalf("running = %d/%d after release, want 0/0", s.running, s.runningContent)
	}
}

// Judges of the same endpoint (several profiles, a reload) share one
// scheduler.
func TestJudgeSchedulerForSharesAnEndpoint(t *testing.T) {
	a := judgeSchedulerFor("http://127.0.0.1:11434/shared-1395", 2)
	b := judgeSchedulerFor(" HTTP://127.0.0.1:11434/shared-1395 ", 3)
	if a == nil || a != b {
		t.Fatalf("schedulers %p %p, want one shared scheduler", a, b)
	}
	if a.limit != 3 {
		t.Fatalf("limit = %d, want the latest max_parallel 3", a.limit)
	}
}
