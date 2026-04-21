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

// Track 0 foundations — stub owned by Track 1 (Agent Identity).
//
// Three-tier agent identity (v7):
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
//
// Track 0 lands the type shell + constructor + getter signatures so
// downstream Tracks (1: agent identity, 7: gateway correlation, 9:
// scanner identity) can call against the API without merge
// conflicts. The real implementation (session eviction, LRU,
// persistence across reloads) ships in Track 1.

import (
	"context"
	"strings"
	"sync"

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

// sessionEntry is the per-session record kept in-memory. Only
// AgentInstanceID is surfaced to observability today; future
// tracks may add last-seen timestamps, request counts, etc.
type sessionEntry struct {
	AgentInstanceID string
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
func (r *AgentRegistry) AgentInstanceForSession(sessionID string) string {
	if r == nil || sessionID == "" {
		return ""
	}
	r.mu.RLock()
	entry, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if ok {
		return entry.AgentInstanceID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok = r.sessions[sessionID]; ok {
		return entry.AgentInstanceID
	}
	entry = sessionEntry{AgentInstanceID: uuid.NewString()}
	r.sessions[sessionID] = entry
	return entry.AgentInstanceID
}

// Resolve returns the three-tier identity for a request context.
// sessionID may be "" (pre-session traffic) in which case only
// AgentID and SidecarInstanceID are populated.
// inboundAgentID, when non-empty, overrides the configured logical agent id
// for this request (HTTP header X-DefenseClaw-Agent-Id).
func (r *AgentRegistry) Resolve(ctx context.Context, sessionID, inboundAgentID string) AgentIdentity {
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
		SidecarInstanceID: r.SidecarInstanceID(),
	}
	if sessionID != "" {
		// agent_instance_id is session-scoped per the observability
		// contract (docs/OBSERVABILITY-CONTRACT.md: "Per conversation").
		// Do NOT mix logicalID into the key — two requests in the
		// same session with different X-DefenseClaw-Agent-Id headers
		// (or one with, one falling back to configured agent.id)
		// must resolve to the same instance id so audit / JSONL /
		// OTel group cleanly per conversation.
		id.AgentInstanceID = r.AgentInstanceForSession(sessionID)
	}
	return id
}

// AgentIdentity is the value object returned by Resolve. The three
// ID fields mirror the gatewaylog.Event envelope 1:1.
type AgentIdentity struct {
	AgentID           string
	AgentName         string
	AgentInstanceID   string
	SidecarInstanceID string
}
