// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"sync"
)

// judgeCallClass orders LLM judge calls when guardrail.judge.max_parallel
// bounds how many of them the gateway sends to the model at once (#1395).
type judgeCallClass uint8

const (
	// judgeCallTool is tool-call judging: the agent waits on it.
	judgeCallTool judgeCallClass = iota
	// judgeCallContent is prompt, completion and adjudication judging.
	judgeCallContent
)

// judgeCallClassOf is the class of a judge call of the given kind.
func judgeCallClassOf(kind string) judgeCallClass {
	if kind == "tool_injection" {
		return judgeCallTool
	}
	return judgeCallContent
}

// judgeScheduler hands out the judge call slots of one model endpoint.
// With a limit of 0 every call starts at once (the behavior before
// max_parallel). With a limit, a waiting tool call gets the next free slot
// before any waiting content call, and content calls never hold the last
// slot when there are two or more, so a tool call never waits behind a
// turn's prompt checks. A wait counts against the call's own deadline.
type judgeScheduler struct {
	mu             sync.Mutex
	limit          int
	running        int
	runningContent int
	waiting        [2][]*judgeSlotWaiter
}

type judgeSlotWaiter struct {
	class   judgeCallClass
	ready   chan struct{}
	granted bool
}

// contentCap is how many slots content calls may hold together.
func (s *judgeScheduler) contentCapLocked() int {
	if s.limit >= 2 {
		return s.limit - 1
	}
	return s.limit
}

func (s *judgeScheduler) canStartLocked(class judgeCallClass) bool {
	if s.limit <= 0 {
		return true
	}
	if s.running >= s.limit {
		return false
	}
	if class == judgeCallTool {
		return true
	}
	return len(s.waiting[judgeCallTool]) == 0 && s.runningContent < s.contentCapLocked()
}

func (s *judgeScheduler) startLocked(class judgeCallClass) {
	s.running++
	if class == judgeCallContent {
		s.runningContent++
	}
}

// dispatchLocked starts waiting calls while slots allow, tool calls first.
func (s *judgeScheduler) dispatchLocked() {
	for {
		class := judgeCallTool
		if len(s.waiting[class]) == 0 {
			class = judgeCallContent
		}
		if len(s.waiting[class]) == 0 {
			return
		}
		// A tool call that cannot start blocks content calls too, so a
		// full gateway does not let content calls take the slot it frees.
		if !s.canStartLocked(class) {
			return
		}
		w := s.waiting[class][0]
		s.waiting[class][0] = nil
		s.waiting[class] = s.waiting[class][1:]
		s.startLocked(class)
		w.granted = true
		close(w.ready)
	}
}

// acquire waits for a slot for a call of class. It returns the release
// function, or ctx's error when ctx ends first. A nil scheduler has no
// limit.
func (s *judgeScheduler) acquire(ctx context.Context, class judgeCallClass) (func(), error) {
	if s == nil {
		return func() {}, nil
	}
	s.mu.Lock()
	if len(s.waiting[class]) == 0 && s.canStartLocked(class) {
		s.startLocked(class)
		s.mu.Unlock()
		return s.releaseFunc(class), nil
	}
	w := &judgeSlotWaiter{class: class, ready: make(chan struct{})}
	s.waiting[class] = append(s.waiting[class], w)
	s.mu.Unlock()
	select {
	case <-w.ready:
		return s.releaseFunc(class), nil
	case <-ctx.Done():
	}
	s.mu.Lock()
	if w.granted {
		// The slot came as ctx ended: pass it on.
		s.releaseLocked(class)
	} else {
		queue := s.waiting[class]
		for i, queued := range queue {
			if queued == w {
				s.waiting[class] = append(queue[:i:i], queue[i+1:]...)
				break
			}
		}
		// A tool call that left may have held back content calls.
		s.dispatchLocked()
	}
	s.mu.Unlock()
	return nil, ctx.Err()
}

func (s *judgeScheduler) releaseFunc(class judgeCallClass) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.releaseLocked(class)
			s.mu.Unlock()
		})
	}
}

func (s *judgeScheduler) releaseLocked(class judgeCallClass) {
	s.running--
	if class == judgeCallContent {
		s.runningContent--
	}
	s.dispatchLocked()
}

// setLimit applies a new max_parallel, starting the calls it now allows.
func (s *judgeScheduler) setLimit(limit int) {
	s.mu.Lock()
	s.limit = max(limit, 0)
	s.dispatchLocked()
	s.mu.Unlock()
}

// queued is how many calls of class wait for a slot.
func (s *judgeScheduler) queued(class judgeCallClass) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiting[class])
}

var (
	judgeSchedulersMu sync.Mutex
	judgeSchedulers   = map[string]*judgeScheduler{}
)

// judgeSchedulerFor is the shared scheduler of one model endpoint, so the
// judges of several guardrail profiles, and the judge built by a config
// reload, share the slots of the server they all call. It applies limit
// (guardrail.judge.max_parallel) to the shared scheduler and returns nil,
// no limit, when limit is 0 and no scheduler exists yet.
func judgeSchedulerFor(endpoint string, limit int) *judgeScheduler {
	key := strings.ToLower(strings.TrimSpace(endpoint))
	judgeSchedulersMu.Lock()
	defer judgeSchedulersMu.Unlock()
	s := judgeSchedulers[key]
	if s == nil {
		if limit <= 0 {
			return nil
		}
		s = &judgeScheduler{}
		judgeSchedulers[key] = s
	}
	s.setLimit(limit)
	return s
}
