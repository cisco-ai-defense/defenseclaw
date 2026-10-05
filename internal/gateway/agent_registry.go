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

// Three-tier agent identity used for runtime correlation.
//
//   - AgentID: logical agent name/id. Stable across restarts and
//     across sidecar processes. Configured via agent.id in
//     config.yaml (AgentConfig). Use for "all events for agent X"
//     grouping in dashboards.
//   - AgentInstanceID: a single agent execution / session. Derived
//     from the agent identity (defenseclaw.agent.identity.id) and the
//     session id ("ais-…", agentidentity.InstanceID), so it is stable
//     across sidecar restarts and two users who send the same session
//     id get different instances. Under the Secure Client integration
//     it stays a random UUID minted on first sight.
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

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
)

// HTTP headers for inbound agent identity correlation.
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

	mu sync.RWMutex
	// sessions caches instances by (agent identity, session). The instance
	// is derived, so the cache only saves the hash and drives LRU eviction.
	sessions map[agentSessionKey]sessionEntry
	// sessionAgents names the one agent identity a session was seen under,
	// so traffic that carries no agent identity (the LLM proxy) joins the
	// hook traffic of the same session. A session seen under two agent
	// identities is ambiguous and joins neither.
	sessionAgents map[string]sessionAgentRef
}

// agentSessionKey is the registry key. agent is "" for traffic that carries
// no agent identity.
type agentSessionKey struct {
	agent   string
	session string
}

type sessionAgentRef struct {
	agent     string
	ambiguous bool
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
		sessions:            make(map[agentSessionKey]sessionEntry),
		sessionAgents:       make(map[string]sessionAgentRef),
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
// for sessionID under no agent identity. See AgentInstanceFor.
func (r *AgentRegistry) AgentInstanceForSession(sessionID string) string {
	id, _ := r.agentInstanceFor("", sessionID)
	return id
}

// AgentInstanceFor returns the instance id of sessionID under the agent
// identity agentIdentityID, minting it the first time the pair is seen. An
// empty sessionID returns "" (no session means no per-session identity) —
// callers should surface that as a missing agent_instance_id field rather
// than synthesising one.
//
// ("Unauthenticated requests can grow the agent
// session registry"): updates LastSeen on every lookup and enforces a
// bounded LRU eviction so a flood of unique session IDs cannot
// permanently grow the registry.
func (r *AgentRegistry) AgentInstanceFor(agentIdentityID, sessionID string) string {
	id, _ := r.agentInstanceFor(agentIdentityID, sessionID)
	return id
}

// agentInstanceFor is AgentInstanceFor that also reports whether this call
// minted the entry, which is how the agent identity recorder counts
// sessions.
func (r *AgentRegistry) agentInstanceFor(agentIdentityID, sessionID string) (string, bool) {
	if r == nil || sessionID == "" {
		return "", false
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keyLocked(agentIdentityID, sessionID)
	if entry, ok := r.sessions[key]; ok {
		// Refresh LastSeen on access so legitimate long-lived
		// sessions stay near the top of the LRU.
		entry.LastSeen = now
		r.sessions[key] = entry
		return entry.AgentInstanceID, false
	}
	if len(r.sessions) >= agentRegistryMaxSessions {
		r.evictOldestLocked()
	}
	instance := agentidentity.InstanceID(key.agent, key.session)
	if ManagedEnterpriseActive() {
		// Secure Client keeps the random, process-scoped instance ids its
		// records have always carried.
		instance = uuid.NewString()
	}
	r.sessions[key] = sessionEntry{AgentInstanceID: instance, LastSeen: now}
	if key.agent != "" {
		ref, seen := r.sessionAgents[key.session]
		switch {
		case !seen:
			r.sessionAgents[key.session] = sessionAgentRef{agent: key.agent}
		case ref.agent != key.agent:
			r.sessionAgents[key.session] = sessionAgentRef{ambiguous: true}
		}
	}
	return instance, true
}

// keyLocked returns the cache key of a lookup. Traffic without an agent
// identity takes the session's agent identity when exactly one is known.
// Caller holds r.mu.
func (r *AgentRegistry) keyLocked(agentIdentityID, sessionID string) agentSessionKey {
	agentIdentityID = strings.TrimSpace(agentIdentityID)
	if agentIdentityID == "" {
		if ref, ok := r.sessionAgents[sessionID]; ok && !ref.ambiguous {
			agentIdentityID = ref.agent
		}
	}
	return agentSessionKey{agent: agentIdentityID, session: sessionID}
}

// evictOldestLocked drops the single oldest session entry to make room
// for a new one. Caller must hold r.mu (write lock). O(N) on registry
// size, which is bounded by agentRegistryMaxSessions, so the worst-case
// eviction cost stays small.
//
// Tie-break: when multiple entries share the same LastSeen (common
// under bursty traffic and unit-test wallclocks with low resolution),
// fall back to key order. Without this tie-break the victim depends on
// Go's randomized map iteration, which makes both behavior and tests
// flaky.
func (r *AgentRegistry) evictOldestLocked() {
	var oldestKey agentSessionKey
	var oldestSeen time.Time
	found := false
	for key, entry := range r.sessions {
		if !found {
			oldestKey, oldestSeen, found = key, entry.LastSeen, true
			continue
		}
		if entry.LastSeen.Before(oldestSeen) {
			oldestKey = key
			oldestSeen = entry.LastSeen
		} else if entry.LastSeen.Equal(oldestSeen) && agentSessionKeyLess(key, oldestKey) {
			oldestKey = key
		}
	}
	if !found {
		return
	}
	delete(r.sessions, oldestKey)
	if ref, ok := r.sessionAgents[oldestKey.session]; ok && (ref.ambiguous || ref.agent == oldestKey.agent) {
		delete(r.sessionAgents, oldestKey.session)
	}
}

func agentSessionKeyLess(a, b agentSessionKey) bool {
	if a.session != b.session {
		return a.session < b.session
	}
	return a.agent < b.agent
}

// AgentIdentityForSession returns the agent identity sessionID was seen under
// on the hook path, or "" when it was seen under none or under more than one.
func (r *AgentRegistry) AgentIdentityForSession(ctx context.Context, sessionID string) string {
	if r == nil || sessionID == "" {
		return ""
	}
	sessionID = sandboxSessionStateKey(ctx, sessionID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if ref, ok := r.sessionAgents[sessionID]; ok && !ref.ambiguous {
		return ref.agent
	}
	return ""
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
	id, _ := r.resolve(ctx, "", sessionID, inboundAgentID, true)
	return id
}

// ResolveForAgentIdentity is Resolve for a request whose agent identity
// (defenseclaw.agent.identity.id) is known. minted reports whether the
// (agent identity, session) pair was new to this registry.
func (r *AgentRegistry) ResolveForAgentIdentity(ctx context.Context, agentIdentityID, sessionID, inboundAgentID string) (id AgentIdentity, minted bool) {
	return r.resolve(ctx, agentIdentityID, sessionID, inboundAgentID, true)
}

// ResolvePeek returns the three-tier identity for a request context
// WITHOUT minting a new entry when sessionID is unknown. The
// AgentInstanceID is left empty for unknown sessions; callers can
// upgrade to Resolve once authentication has succeeded. // S2.MEDIUM ("CorrelationMiddleware mints unauthenticated agent
// sessions") closure: combined with the AgentRegistry LRU cap, this
// stops unauthenticated requests from amplifying memory usage by
// flooding distinct X-DefenseClaw-Session-Id headers.
func (r *AgentRegistry) ResolvePeek(ctx context.Context, sessionID, inboundAgentID string) AgentIdentity {
	id, _ := r.resolve(ctx, "", sessionID, inboundAgentID, false)
	return id
}

func (r *AgentRegistry) resolve(ctx context.Context, agentIdentityID, sessionID, inboundAgentID string, mint bool) (AgentIdentity, bool) {
	// A sandbox's sessions are kept apart from the host's and from every
	// other sandbox's, whatever session IDs the agents choose.
	sessionID = sandboxSessionStateKey(ctx, sessionID)
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
	minted := false
	if sessionID != "" {
		if mint {
			// agent_instance_id is session-scoped so every record for one
			// conversation resolves to the same execution identity.
			id.AgentInstanceID, minted = r.agentInstanceFor(agentIdentityID, sessionID)
		} else {
			id.AgentInstanceID = r.peekAgentInstance(agentIdentityID, sessionID)
		}
	}
	return id, minted
}

// peekAgentInstance returns the existing instance id for sessionID
// without minting a new entry. Updates LastSeen on hit so the LRU
// reflects observed activity even from peek-only callers.
func (r *AgentRegistry) peekAgentInstance(agentIdentityID, sessionID string) string {
	if r == nil || sessionID == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keyLocked(agentIdentityID, sessionID)
	entry, ok := r.sessions[key]
	if !ok {
		return ""
	}
	entry.LastSeen = time.Now()
	r.sessions[key] = entry
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
	UserIDKind        string
	UserName          string
	// IdentityID is defenseclaw.agent.identity.id ("agt-…"), set on the hook
	// path after authentication. Empty under the Secure Client integration
	// and on traffic with no hook identity.
	IdentityID string
	// IdentityVerified is true when every component of IdentityID came from
	// a verified source. See agentIdentityFromContext.
	IdentityVerified bool
}
