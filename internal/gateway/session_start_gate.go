// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// sessionStartGate holds each agent session's start verdict in this gateway
// process (GAP-0806). A session start can take long (a slow scan, a
// registration repair, a starting Windows service) while the agent goes on
// to its first prompt and tool call: an agent does not stop when its start
// hook times out. A call of a session whose start the gateway is still
// judging therefore waits for that verdict, and is refused when it does not
// come in time. A start the gateway blocked keeps refusing the session's
// calls until the agent starts the session again.
type sessionStartGate struct {
	mu      sync.Mutex
	entries map[string]*sessionStartEntry
}

type sessionStartEntry struct {
	// done is closed once blocked and reason are final.
	done    chan struct{}
	blocked bool
	reason  string
	at      time.Time
}

// sessionStartTicket is one session start being judged.
type sessionStartTicket struct {
	gate  *sessionStartGate
	key   string
	entry *sessionStartEntry
	once  sync.Once
}

const (
	// sessionStartGateLimit bounds the sessions kept. A start being judged
	// is never dropped; a blocked one is dropped oldest first.
	sessionStartGateLimit = 4096
	// sessionStartGateTTL is how long a blocked start keeps refusing.
	sessionStartGateTTL = 7 * 24 * time.Hour
	// sessionStartPendingReason refuses a call whose session start is still
	// being judged after the wait.
	sessionStartPendingReason = "DefenseClaw has not finished checking this agent session's start, so it blocks this call. Try again in a moment; if this repeats, restart the agent."
	// sessionStartUnfinishedReason is a start that ended without a verdict.
	sessionStartUnfinishedReason = "the session start check did not finish"
)

// sessionStartGateMaxWait bounds how long a call waits for its session's
// start verdict (a variable for tests).
var sessionStartGateMaxWait = 10 * time.Second

// sessionStartGateKey names a session for the gate: the connector, the
// verified caller and the session ID (scoped to a sandbox binding). "" when
// the call names no session.
func sessionStartGateKey(ctx context.Context, connectorName, sessionID string) string {
	session := sandboxSessionStateKey(ctx, strings.TrimSpace(sessionID))
	if session == "" {
		return ""
	}
	caller := ""
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		caller = "uid:" + strconv.Itoa(peer.UID)
	} else if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
		caller = "user:" + identity
	}
	return strings.ToLower(strings.TrimSpace(connectorName)) + "\x00" + caller + "\x00" + session
}

// sessionStartGateEvent reports a call the gate holds back: a prompt or a
// tool call. Lifecycle and result events cannot run anything.
func sessionStartGateEvent(event string) bool {
	switch canonicalHookLifecycleEvent(event) {
	case "turn_start", "tool_start":
		return true
	}
	return false
}

// sessionStartGateWait is how long a call waits: half of its hook's request
// budget, at most sessionStartGateMaxWait, so the refusal reaches the agent
// before the hook gives up.
func sessionStartGateWait(connectorName, event string) time.Duration {
	wait := hookexec.RequestTimeout(connectorName, event) / 2
	if wait <= 0 || wait > sessionStartGateMaxWait {
		wait = sessionStartGateMaxWait
	}
	return wait
}

// begin records a session start being judged. A later start of the same
// session replaces the earlier verdict.
func (g *sessionStartGate) begin(key string) *sessionStartTicket {
	if g == nil || key == "" {
		return nil
	}
	entry := &sessionStartEntry{done: make(chan struct{}), at: time.Now()}
	g.mu.Lock()
	if g.entries == nil {
		g.entries = make(map[string]*sessionStartEntry)
	}
	if len(g.entries) >= sessionStartGateLimit {
		g.evictLocked(time.Now())
	}
	g.entries[key] = entry
	g.mu.Unlock()
	return &sessionStartTicket{gate: g, key: key, entry: entry}
}

// evictLocked drops expired blocks, then the oldest finished ones until the
// gate is under its limit.
func (g *sessionStartGate) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, entry := range g.entries {
		select {
		case <-entry.done:
		default:
			continue
		}
		if now.Sub(entry.at) > sessionStartGateTTL {
			delete(g.entries, key)
			continue
		}
		if oldestKey == "" || entry.at.Before(oldest) {
			oldestKey, oldest = key, entry.at
		}
	}
	if len(g.entries) >= sessionStartGateLimit && oldestKey != "" {
		delete(g.entries, oldestKey)
	}
}

// finish records the start's verdict and releases the calls waiting for it.
// Only the first call counts. An allowed start leaves nothing behind.
func (t *sessionStartTicket) finish(blocked bool, reason string) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		g := t.gate
		g.mu.Lock()
		t.entry.blocked, t.entry.reason, t.entry.at = blocked, reason, time.Now()
		if !blocked && g.entries[t.key] == t.entry {
			delete(g.entries, t.key)
		}
		g.mu.Unlock()
		close(t.entry.done)
	})
}

// await returns the reason to refuse a call of the session: its start was
// blocked, or is still being judged after wait (or when ctx ends).
func (g *sessionStartGate) await(ctx context.Context, key string, wait time.Duration) (string, bool) {
	if g == nil || key == "" {
		return "", false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		g.mu.Lock()
		entry := g.entries[key]
		g.mu.Unlock()
		if entry == nil {
			return "", false
		}
		select {
		case <-entry.done:
			if entry.blocked {
				if time.Since(entry.at) > sessionStartGateTTL {
					g.mu.Lock()
					if g.entries[key] == entry {
						delete(g.entries, key)
					}
					g.mu.Unlock()
					return "", false
				}
				return sessionStartBlockedReason(entry.reason), true
			}
			// The verdict allowed the start; a newer start may be pending.
			continue
		default:
		}
		select {
		case <-entry.done:
		case <-timer.C:
			return sessionStartPendingReason, true
		case <-ctx.Done():
			return sessionStartPendingReason, true
		}
	}
}

func sessionStartBlockedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 400 {
		reason = reason[:400]
	}
	if reason == "" {
		reason = sessionStartUnfinishedReason
	}
	return "DefenseClaw blocked this agent session when it started (" + reason + "), so it blocks this call. Restart the agent."
}

// sessionStartVerdictBlocks reports a start verdict that blocks the session:
// an enforced block, whether or not the agent's start event can stop it.
func sessionStartVerdictBlocks(resp agentHookResponse) bool {
	return strings.EqualFold(resp.RawAction, guardrailActionBlock) && resp.Mode == "action"
}

// sessionStartGateRefusal answers a call the gate refuses, in the
// connector's verdict shape and mode.
func (a *APIServer) sessionStartGateRefusal(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	payload map[string]interface{},
	reason string,
) agentHookResponse {
	finding := "SESSION-START-BLOCKED"
	if reason == sessionStartPendingReason {
		finding = "SESSION-START-PENDING"
	}
	mode := sandboxHookMode(ctx, connectorName, a.agentHookMode(ctx, connectorName))
	action, wouldBlock := mapHookActionForProfile("block", mode, req.HookEventName, profile.Capabilities, profile, payload)
	return agentHookResponseForProfile(profile, req, action, "block", "HIGH", reason,
		[]string{finding}, mode, wouldBlock, profile.Capabilities)
}
