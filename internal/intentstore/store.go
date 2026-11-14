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

// Package intentstore keeps the tool judge's per-session context: the
// latest bounded user intent of a session and its recent tool calls. The
// gateway's judge reads and writes it through Store. A gateway on one
// machine uses the process-local Process (the default); a gateway with
// several replicas puts a shared store behind the same interface, so every
// replica judges a session's tool call with the same intent.
//
// Everything kept is untrusted data: the judge quotes it in its sample and
// never follows it. Values arrive already bounded by the judge.
package intentstore

import (
	"context"
	"sync"
	"time"
)

// ToolCall is one recorded tool call: the sanitized tool name and the
// bounded argument excerpt.
type ToolCall struct {
	Tool string
	Args string
}

// Snapshot is a session's context as a tool call found it.
type Snapshot struct {
	// UserIntent is the latest bounded user prompt, or "".
	UserIntent string
	// Prior are the tool calls before the current one, oldest first.
	Prior []ToolCall
}

// Store keeps the context of each session key (the judge's session state
// key: connector scope and session ID). An implementation must order the
// calls of one key: AppendToolCall returns what the calls before it left.
type Store interface {
	// ObservePrompt starts key's context over with intent: a new user
	// prompt starts a new tool chain, so the prior calls are dropped.
	ObservePrompt(ctx context.Context, key, intent string) error
	// AppendToolCall records call under key and returns key's context as it
	// was before the call.
	AppendToolCall(ctx context.Context, key string, call ToolCall) (Snapshot, error)
	// Reset drops key's context (a new or ended session).
	Reset(ctx context.Context, key string) error
}

// Limits bound a Process store.
type Limits struct {
	// MaxSessions is how many keys are kept; a full store first drops the
	// keys idle for TTL, then the least recently used.
	MaxSessions int
	// MaxPrior is how many tool calls a key keeps.
	MaxPrior int
	// TTL is how long an idle key survives a full store's prune.
	TTL time.Duration
}

// Process is the process-local Store: a bounded map, lost on restart.
type Process struct {
	limits Limits
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]processSession
}

type processSession struct {
	userIntent string
	events     []ToolCall
	lastSeen   time.Time
}

// NewProcess returns an empty process-local store.
func NewProcess(limits Limits) *Process {
	return &Process{limits: limits, now: time.Now}
}

var _ Store = (*Process)(nil)

// ObservePrompt implements Store.
func (p *Process) ObservePrompt(_ context.Context, key, intent string) error {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.roomLocked(now)
	p.sessions[key] = processSession{userIntent: intent, lastSeen: now}
	return nil
}

// AppendToolCall implements Store.
func (p *Process) AppendToolCall(_ context.Context, key string, call ToolCall) (Snapshot, error) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.roomLocked(now)
	entry := p.sessions[key]
	prior := append([]ToolCall(nil), entry.events...)
	entry.events = append(entry.events, call)
	if max := p.limits.MaxPrior; len(entry.events) > max {
		entry.events = append([]ToolCall(nil), entry.events[len(entry.events)-max:]...)
	}
	entry.lastSeen = now
	p.sessions[key] = entry
	return Snapshot{UserIntent: entry.userIntent, Prior: prior}, nil
}

// Reset implements Store.
func (p *Process) Reset(_ context.Context, key string) error {
	p.mu.Lock()
	delete(p.sessions, key)
	p.mu.Unlock()
	return nil
}

// Peek returns key's context without recording anything (tests and
// diagnostics).
func (p *Process) Peek(key string) (Snapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.sessions[key]
	return Snapshot{UserIntent: entry.userIntent, Prior: append([]ToolCall(nil), entry.events...)}, ok
}

// CallCount returns how many tool calls the store holds across every
// session key (tests and diagnostics, like Peek).
func (p *Process) CallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, entry := range p.sessions {
		n += len(entry.events)
	}
	return n
}

// roomLocked makes the map and, when it is full, prunes it: the keys idle
// for TTL first, then the least recently used until one is free.
func (p *Process) roomLocked(now time.Time) {
	if p.sessions == nil {
		p.sessions = make(map[string]processSession)
	}
	if len(p.sessions) < p.limits.MaxSessions {
		return
	}
	for key, entry := range p.sessions {
		if now.Sub(entry.lastSeen) >= p.limits.TTL {
			delete(p.sessions, key)
		}
	}
	for len(p.sessions) >= p.limits.MaxSessions {
		oldestKey := ""
		var oldest time.Time
		for key, entry := range p.sessions {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey, oldest = key, entry.lastSeen
			}
		}
		if oldestKey == "" {
			break
		}
		delete(p.sessions, oldestKey)
	}
}
