// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// Three-tier agent identity (v7 correlation).
//
//   - AgentID: logical agent name/id. Stable across restarts and
//     across sidecar processes. Configured via agent.id in
//     config.yaml (AgentConfig). Use for "all events for agent X"
//     grouping in dashboards.
//   - AgentInstanceID: a single agent execution / session. Minted
//     when the first request for that session is observed by the
//     sidecar; persists for the lifetime of the session.
//   - SidecarInstanceID: the sidecar process. Minted exactly once
//     at boot and stable for the process lifetime. Primarily
//     useful for operators debugging which sidecar emitted an
//     event after the fact.
//
// The registry is the single owner of these three identifiers.
// Every observability emission (audit, gatewaylog, OTel) reads
// them through this type; no other package mints or mutates them.
// Downstream subsystems (gateway correlation middleware, scanner
// identity propagation, agent-scoped policy lookups) call against
// this API so they all see the same three-tier identity for a
// given request.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// HTTP headers for inbound agent identity (v7 correlation).
const (
	AgentIDHeader         = "X-DefenseClaw-Agent-Id"
	AgentInstanceIDHeader = "X-DefenseClaw-Agent-Instance-Id"
	RunIDHeader           = "X-DefenseClaw-Run-Id"
	PolicyIDHeader        = "X-DefenseClaw-Policy-Id"
	ResponseAgentIDHeader = AgentIDHeader // echoed on response for debuggability
)

var (
	sharedRegMu sync.Mutex
	sharedReg   *AgentRegistry
)

// InstallSharedAgentRegistry returns the process-wide registry, creating it on
// first call. Later calls with a non-empty agent id upgrade a previously empty
// configured id (API server may initialize after the guardrail proxy).
func InstallSharedAgentRegistry(agentID, agentName string) *AgentRegistry {
	sharedRegMu.Lock()
	defer sharedRegMu.Unlock()
	if sharedReg == nil {
		sharedReg = NewAgentRegistry(agentID, agentName)
		return sharedReg
	}
	sharedReg.mergeConfiguredIdentity(agentID, agentName)
	return sharedReg
}

// SharedAgentRegistry returns the installed registry, or nil if
// InstallSharedAgentRegistry has not run.
func SharedAgentRegistry() *AgentRegistry {
	sharedRegMu.Lock()
	defer sharedRegMu.Unlock()
	return sharedReg
}

// AgentRegistry tracks the three-tier agent identity for the
// lifetime of a single sidecar process. All methods are safe to
// call from multiple goroutines.
//
// Zero value is not usable; construct via NewAgentRegistry.
type AgentRegistry struct {
	// sidecarInstanceID is minted exactly once at construction and
	// never mutated — readers do not need the lock for this field.
	sidecarInstanceID string

	// configuredAgentID is the logical agent id from config.yaml
	// (agent.id). Empty string means "not configured" and
	// downstream callers should fall back to the per-session
	// default.
	configuredAgentID   string
	configuredAgentName string

	mu       sync.RWMutex
	sessions map[string]sessionEntry // session_id -> instance
}

// ("Unauthenticated requests can grow the agent
// session registry"): the legacy registry minted and retained an entry
// for every distinct X-DefenseClaw-Session-Id, with no TTL or LRU cap.
// CorrelationMiddleware ran before tokenAuth, so an unauthenticated
// caller could send a flood of unique IDs to /health (or even to
// rejected-auth paths) and grow the in-memory map without bound.
//
// The cap below is intentionally generous (legitimate sidecars rarely
// exceed a few hundred concurrent sessions) but strict enough to bound
// the per-process memory cost. When the cap is exceeded we evict the
// oldest entries first; this keeps long-lived sessions stable while
// shedding rotated/spoofed IDs.
const agentRegistryMaxSessions = 4096

// sessionEntry is the per-session record kept in-memory. “LastSeen“
// powers oldest-first eviction once the registry grows past the cap;
// “AgentInstanceID“ is the value surfaced to observability today.
type sessionEntry struct {
	AgentInstanceID string
	LastSeen        time.Time
}

// NewAgentRegistry constructs a registry with a fresh sidecar
// instance id and the configured agent identity (may be empty).
// Call exactly once at sidecar boot; pass the result to every
// observability writer that needs agent identity.
func NewAgentRegistry(agentID, agentName string) *AgentRegistry {
	return &AgentRegistry{
		sidecarInstanceID:   uuid.NewString(),
		configuredAgentID:   agentID,
		configuredAgentName: agentName,
		sessions:            make(map[string]sessionEntry),
	}
}

func (r *AgentRegistry) mergeConfiguredIdentity(agentID, agentName string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if agentID != "" && r.configuredAgentID == "" {
		r.configuredAgentID = agentID
	}
	if agentName != "" && r.configuredAgentName == "" {
		r.configuredAgentName = agentName
	}
}

// SidecarInstanceID returns the UUID minted at sidecar boot.
// Stable for the process lifetime; rotates on every restart.
func (r *AgentRegistry) SidecarInstanceID() string {
	if r == nil {
		return ""
	}
	return r.sidecarInstanceID
}

// AgentID returns the configured logical agent id, or "" when
// config.yaml did not set agent.id. Callers are responsible for
// falling back to a per-session default if "" is unacceptable.
func (r *AgentRegistry) AgentID() string {
	if r == nil {
		return ""
	}
	return r.configuredAgentID
}

// AgentName returns the configured human-readable agent name, or "".
func (r *AgentRegistry) AgentName() string {
	if r == nil {
		return ""
	}
	return r.configuredAgentName
}

// AgentInstanceForSession returns the per-session agent instance id
// for sessionID, minting a fresh v4 UUID the first time a session is
// seen. An empty sessionID returns "" (no session means no
// per-session identity) — callers should surface that as a missing
// agent_instance_id field rather than synthesising one.
//
// ("Unauthenticated requests can grow the agent
// session registry"): updates LastSeen on every lookup and enforces a
// bounded LRU eviction so a flood of unique session IDs cannot
// permanently grow the registry.
func (r *AgentRegistry) AgentInstanceForSession(sessionID string) string {
	if r == nil || sessionID == "" {
		return ""
	}
	now := time.Now()
	r.mu.RLock()
	entry, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if ok {
		// Refresh LastSeen on access so legitimate long-lived
		// sessions stay near the top of the LRU.
		r.mu.Lock()
		if existing, stillThere := r.sessions[sessionID]; stillThere {
			existing.LastSeen = now
			r.sessions[sessionID] = existing
		}
		r.mu.Unlock()
		return entry.AgentInstanceID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok = r.sessions[sessionID]; ok {
		entry.LastSeen = now
		r.sessions[sessionID] = entry
		return entry.AgentInstanceID
	}
	if len(r.sessions) >= agentRegistryMaxSessions {
		r.evictOldestLocked()
	}
	entry = sessionEntry{AgentInstanceID: uuid.NewString(), LastSeen: now}
	r.sessions[sessionID] = entry
	return entry.AgentInstanceID
}

// evictOldestLocked drops the single oldest session entry to make room
// for a new one. Caller must hold r.mu (write lock). O(N) on registry
// size, which is bounded by agentRegistryMaxSessions, so the worst-case
// eviction cost stays small.
//
// Tie-break: when multiple entries share the same LastSeen (common
// under bursty traffic and unit-test wallclocks with low resolution),
// fall back to lexicographic key order. Without this tie-break the
// victim depends on Go's randomized map iteration, which makes both
// behavior and tests flaky.
func (r *AgentRegistry) evictOldestLocked() {
	var oldestKey string
	var oldestSeen time.Time
	for key, entry := range r.sessions {
		if oldestKey == "" {
			oldestKey = key
			oldestSeen = entry.LastSeen
			continue
		}
		if entry.LastSeen.Before(oldestSeen) {
			oldestKey = key
			oldestSeen = entry.LastSeen
		} else if entry.LastSeen.Equal(oldestSeen) && key < oldestKey {
			oldestKey = key
		}
	}
	if oldestKey != "" {
		delete(r.sessions, oldestKey)
	}
}

// Resolve returns the three-tier identity for a request context.
// sessionID may be "" (pre-session traffic) in which case only
// AgentID and SidecarInstanceID are populated.
// inboundAgentID, when non-empty, overrides the configured logical agent id
// for this request (HTTP header X-DefenseClaw-Agent-Id).
//
// Resolve mints a new agent_instance_id when the session is new.
// Authenticated callers should use Resolve; unauthenticated middleware
// should use ResolvePeek to avoid letting unauthenticated traffic
// grow the session map.
func (r *AgentRegistry) Resolve(ctx context.Context, sessionID, inboundAgentID string) AgentIdentity {
	return r.resolve(ctx, sessionID, inboundAgentID, true)
}

// ResolvePeek returns the three-tier identity for a request context
// WITHOUT minting a new entry when sessionID is unknown. The
// AgentInstanceID is left empty for unknown sessions; callers can
// upgrade to Resolve once authentication has succeeded. // S2.MEDIUM ("CorrelationMiddleware mints unauthenticated agent
// sessions") closure: combined with the AgentRegistry LRU cap, this
// stops unauthenticated requests from amplifying memory usage by
// flooding distinct X-DefenseClaw-Session-Id headers.
func (r *AgentRegistry) ResolvePeek(ctx context.Context, sessionID, inboundAgentID string) AgentIdentity {
	return r.resolve(ctx, sessionID, inboundAgentID, false)
}

func (r *AgentRegistry) resolve(ctx context.Context, sessionID, inboundAgentID string, mint bool) AgentIdentity {
	_ = ctx
	logicalID := strings.TrimSpace(inboundAgentID)
	if logicalID == "" {
		logicalID = r.AgentID()
	}
	logicalName := r.AgentName()
	if logicalID != "" && logicalName == "" {
		logicalName = logicalID
	}
	id := AgentIdentity{
		AgentID:           logicalID,
		AgentName:         logicalName,
		AgentType:         logicalName,
		SidecarInstanceID: r.SidecarInstanceID(),
	}
	if sessionID != "" {
		if mint {
			// agent_instance_id is session-scoped per the observability
			// contract (docs/OBSERVABILITY-CONTRACT.md: "Per conversation").
			id.AgentInstanceID = r.AgentInstanceForSession(sessionID)
		} else {
			id.AgentInstanceID = r.peekAgentInstance(sessionID)
		}
	}
	return id
}

// peekAgentInstance returns the existing instance id for sessionID
// without minting a new entry. Updates LastSeen on hit so the LRU
// reflects observed activity even from peek-only callers.
func (r *AgentRegistry) peekAgentInstance(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	now := time.Now()
	r.mu.RLock()
	entry, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return ""
	}
	r.mu.Lock()
	if existing, stillThere := r.sessions[sessionID]; stillThere {
		existing.LastSeen = now
		r.sessions[sessionID] = existing
	}
	r.mu.Unlock()
	return entry.AgentInstanceID
}

// AgentIdentity is the value object returned by Resolve. The three
// ID fields mirror the gatewaylog.Event envelope 1:1.
type AgentIdentity struct {
	AgentID           string
	AgentName         string
	AgentType         string
	AgentInstanceID   string
	SidecarInstanceID string
	UserID            string
	UserName          string
}
