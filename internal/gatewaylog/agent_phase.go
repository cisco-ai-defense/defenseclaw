// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import "strings"

// Canonical agent phases. These values are the Go-side projection of the
// AgentPhase definition in gateway-event-envelope.json. The runtime schema is
// the wire authority; TestAgentPhaseContractMatchesRuntimeSchema prevents this
// projection (and its durable numeric codes) from drifting from that contract.
const (
	AgentPhaseSession     = "session"
	AgentPhasePlanning    = "planning"
	AgentPhaseModel       = "model"
	AgentPhaseTool        = "tool"
	AgentPhaseApproval    = "approval"
	AgentPhaseWaiting     = "waiting"
	AgentPhaseResponding  = "responding"
	AgentPhaseMaintenance = "maintenance"
	AgentPhaseCompleted   = "completed"
	AgentPhaseFailed      = "failed"
	AgentPhaseInterrupted = "interrupted"
	AgentPhaseObserved    = "observed"
)

var canonicalAgentPhases = [...]string{
	AgentPhaseSession,
	AgentPhasePlanning,
	AgentPhaseModel,
	AgentPhaseTool,
	AgentPhaseApproval,
	AgentPhaseWaiting,
	AgentPhaseResponding,
	AgentPhaseMaintenance,
	AgentPhaseCompleted,
	AgentPhaseFailed,
	AgentPhaseInterrupted,
	AgentPhaseObserved,
}

// CanonicalAgentPhases returns a copy of the ordered phase vocabulary. Its
// order is stable because AgentPhaseCode uses the same 1-based positions for
// historical Prometheus/Grafana samples.
func CanonicalAgentPhases() []string {
	return append([]string(nil), canonicalAgentPhases[:]...)
}

// NormalizeAgentPhase canonicalizes known phase spellings. It accepts casing,
// whitespace, and only aliases whose meaning is unambiguous. The boolean is
// false for empty or unsupported values; callers decide whether an unsupported
// required/current phase should fail closed or an optional previous phase
// should be omitted.
func NormalizeAgentPhase(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AgentPhaseSession:
		return AgentPhaseSession, true
	case AgentPhasePlanning, "plan":
		return AgentPhasePlanning, true
	case AgentPhaseModel, "inference":
		return AgentPhaseModel, true
	case AgentPhaseTool, "tool-call", "tool_call", "tool-use", "tool_use":
		return AgentPhaseTool, true
	case AgentPhaseApproval, "permission":
		return AgentPhaseApproval, true
	case AgentPhaseWaiting, "idle":
		return AgentPhaseWaiting, true
	case AgentPhaseResponding, "response":
		return AgentPhaseResponding, true
	case AgentPhaseMaintenance, "compaction":
		return AgentPhaseMaintenance, true
	case AgentPhaseCompleted, "complete":
		return AgentPhaseCompleted, true
	case AgentPhaseFailed, "failure", "error":
		return AgentPhaseFailed, true
	case AgentPhaseInterrupted, "canceled", "cancelled":
		return AgentPhaseInterrupted, true
	case AgentPhaseObserved, "observation":
		return AgentPhaseObserved, true
	default:
		return "", false
	}
}

// AgentPhaseCode is the durable numeric phase vocabulary. Zero is reserved for
// an absent/unsupported phase and is not a schema-valid textual phase.
func AgentPhaseCode(raw string) int {
	phase, ok := NormalizeAgentPhase(raw)
	if !ok {
		return 0
	}
	for i, candidate := range canonicalAgentPhases {
		if phase == candidate {
			return i + 1
		}
	}
	return 0
}

// normalizeEventAgentPhases runs at the Writer choke point before runtime
// schema validation. A recognized current phase is canonicalized; an unknown
// current phase is preserved so the strict schema still rejects malformed
// events. agent_previous_phase is optional, so unsupported values are omitted
// rather than causing an otherwise valid, correlated event to be dropped.
func normalizeEventAgentPhases(event *Event) {
	if event == nil {
		return
	}
	if phase, ok := NormalizeAgentPhase(event.AgentPhase); ok {
		event.AgentPhase = phase
	}
	if previous, ok := NormalizeAgentPhase(event.AgentPreviousPhase); ok {
		event.AgentPreviousPhase = previous
	} else {
		event.AgentPreviousPhase = ""
	}
}
