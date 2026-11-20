// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package copilotjoin keeps the calls an argumentless native GitHub Copilot
// permissionRequest callback can stand for: the calls of the one recent,
// audited, allowed preToolUse of the same verified caller, session and
// directory. The gateway decides the bound call again, now; this package
// only keeps which calls those are, and consumes them.
//
// A gateway on one machine uses its own Process. A gateway with several
// replicas (Agent Substrate) puts the leader's Process behind the same
// Store, keyed by the verified actor, because a preToolUse and its callback
// can land on different replicas (substrate-1 GAP-0269).
package copilotjoin

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
)

const (
	// TTL is how long a recorded preToolUse can be joined.
	TTL = 8 * time.Second
	// Max bounds the entries of one Process.
	Max = 4096
)

// Entry is what a callback takes: the calls of one allowed preToolUse (one,
// or those of a parallel toolCalls envelope) that its tool can stand for.
// An argumentless callback cannot say which of them it is for, so it is
// bound to all of them and decided again on each (the most restrictive
// verdict answers); Uses callbacks consume the entry (GAP-1831).
type Entry struct {
	At        time.Time
	Ambiguous bool
	Calls     []copilotargs.NativeCall
	Uses      int
}

// Store keeps the entries of every scope (a verified caller, session and
// directory).
type Store interface {
	// Record notes one audited preToolUse of scope: its calls, whether they
	// could be read and whether the call was allowed.
	Record(ctx context.Context, scope string, readable, allowed bool, calls []copilotargs.NativeCall) error
	// Take consumes what one callback of tool in scope stands for.
	Take(ctx context.Context, scope, tool string) (Entry, bool, error)
}

// CallbackTool is the tool name of the permissionRequest a call's callback
// carries: apply_patch and create calls ask as edit. Entries are kept per
// callback tool, because a callback can stand only for a call of its own
// tool: a call of another tool (a read, or a shell command the agent
// approves itself) never gets this callback, so it can neither be bound to
// it nor make it ambiguous (GAP-1924). A create callback carries its own
// arguments; keyed with the patches of its envelope it takes its own use
// instead of the one an argumentless patch callback needs (GAP-1961).
func CallbackTool(tool string) string {
	tool = strings.TrimSpace(tool)
	if tool == "apply_patch" || tool == "create" {
		return "edit"
	}
	return tool
}

// ToolKey is the key of the entry of scope's callbacks of tool.
func ToolKey(scope, tool string) string {
	return scope + "\x00" + CallbackTool(tool)
}

// callsNeedTheJoin reports whether an argumentless callback can stand for
// one of the calls: every call but a create or edit, whose callbacks always
// carry their own arguments.
func callsNeedTheJoin(calls []copilotargs.NativeCall) bool {
	for _, call := range calls {
		if name := strings.TrimSpace(call.Name); name != "create" && name != "edit" {
			return true
		}
	}
	return false
}

// Process is the process-local Store. The zero value is ready to use.
type Process struct {
	mu      sync.Mutex
	entries map[string]Entry
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

var _ Store = (*Process)(nil)

func (p *Process) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Record implements Store: it keeps the calls of an allowed preToolUse,
// one entry per callback tool. Any other preToolUse in the same scope within
// the lifetime, allowed or not, leaves the next callback of the same tool
// ambiguous; a preToolUse whose calls cannot be read leaves every callback
// of the scope ambiguous.
func (p *Process) Record(_ context.Context, scope string, readable, allowed bool, calls []copilotargs.NativeCall) error {
	if scope == "" {
		return nil
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = make(map[string]Entry)
	}
	if !readable {
		for key, prior := range p.entries {
			if strings.HasPrefix(key, scope+"\x00") && now.Sub(prior.At) <= TTL {
				prior.Ambiguous = true
				prior.At = now
				p.entries[key] = prior
			}
		}
		return nil
	}
	byKey := make(map[string][]copilotargs.NativeCall)
	var keys []string
	for _, call := range calls {
		key := ToolKey(scope, call.Name)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], copilotargs.NativeCall{Name: call.Name, Args: append(json.RawMessage(nil), call.Args...)})
	}
	for _, key := range keys {
		if prior, exists := p.entries[key]; exists && now.Sub(prior.At) <= TTL {
			prior.Ambiguous = true
			prior.At = now
			p.entries[key] = prior
			continue
		}
		// A call whose own callback carries its arguments (create and edit
		// ask with {file_path, diff}) never needs the join, so it is not
		// kept: when its callback does not arrive, it cannot make the next
		// patch's argumentless callback ambiguous (GAP-2012). It still makes
		// a live entry of its tool ambiguous (above), and inside an envelope
		// with a patch it still counts as a use (GAP-1961).
		if !allowed || !callsNeedTheJoin(byKey[key]) {
			continue
		}
		if len(p.entries) >= Max {
			for old, entry := range p.entries {
				if now.Sub(entry.At) > TTL {
					delete(p.entries, old)
				}
			}
			if len(p.entries) >= Max {
				continue
			}
		}
		p.entries[key] = Entry{Calls: byKey[key], Uses: len(byKey[key]), At: now}
	}
	return nil
}

// Take implements Store. Every callback consumes one use of the prior calls
// of its tool, bound or not, so no later callback can reuse them. A callback
// no preToolUse of its tool announced means the join lost track of the
// session's calls: it consumes every prior call of the scope, so none is
// bound to a later callback.
func (p *Process) Take(_ context.Context, scope, tool string) (Entry, bool, error) {
	if scope == "" {
		return Entry{}, false, nil
	}
	key := ToolKey(scope, tool)
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, exists := p.entries[key]
	if exists && now.Sub(entry.At) > TTL {
		delete(p.entries, key)
		exists = false
	}
	if !exists {
		for other := range p.entries {
			if strings.HasPrefix(other, scope+"\x00") {
				delete(p.entries, other)
			}
		}
		return Entry{}, false, nil
	}
	if entry.Uses > 1 {
		kept := entry
		kept.Uses--
		p.entries[key] = kept
	} else {
		delete(p.entries, key)
	}
	return entry, true, nil
}
