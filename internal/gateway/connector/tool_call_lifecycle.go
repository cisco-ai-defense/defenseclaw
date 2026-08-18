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

package connector

import (
	"fmt"
	"strings"
)

// ToolCallLifecycleContractVersion is independent of the inventory manifest
// schema and of each vendor hook contract version. It versions the meaning of
// the lifecycle fields below so stateful enforcement never guesses at an old
// manifest's semantics.
const ToolCallLifecycleContractVersion = 1

// ToolInvocationIDAuthority describes the strongest connector-owned identity
// that can join a proposal to a later result.
type ToolInvocationIDAuthority string

const (
	ToolInvocationIDNone           ToolInvocationIDAuthority = "none"
	ToolInvocationIDPairedID       ToolInvocationIDAuthority = "paired-id"
	ToolInvocationIDPairedSequence ToolInvocationIDAuthority = "paired-sequence"
)

// ToolOutcomeAuthority describes how an event proves a tool outcome. A result
// payload authority requires a connector-specific status/error predicate; the
// event name alone is not evidence of success.
type ToolOutcomeAuthority string

const (
	ToolOutcomeNone            ToolOutcomeAuthority = "none"
	ToolOutcomeEventKind       ToolOutcomeAuthority = "event-kind"
	ToolOutcomeResultPayload   ToolOutcomeAuthority = "result-payload"
	ToolOutcomeSurfaceSpecific ToolOutcomeAuthority = "surface-specific"
)

// StatefulToolEnforcementLevel is deliberately conservative. Detection-only
// contracts may inspect result content and emit findings, but those results do
// not independently commit a cross-event state transition. Paired-outcomes is
// reserved for contracts with both a usable invocation identity and an
// authoritative outcome.
type StatefulToolEnforcementLevel string

const (
	StatefulToolDirectOnly     StatefulToolEnforcementLevel = "direct-only"
	StatefulToolDetectionOnly  StatefulToolEnforcementLevel = "detection-only"
	StatefulToolPairedOutcomes StatefulToolEnforcementLevel = "paired-outcomes"
)

// ToolSurface is a closed vocabulary for tool families covered by the hook
// contract. Absence is meaningful: it means coverage has not been established
// and must not be inferred from another surface.
type ToolSurface string

const (
	ToolSurfaceGeneric   ToolSurface = "generic"
	ToolSurfaceShell     ToolSurface = "shell"
	ToolSurfaceFileRead  ToolSurface = "file-read"
	ToolSurfaceFileWrite ToolSurface = "file-write"
	ToolSurfaceFileEdit  ToolSurface = "file-edit"
	ToolSurfaceMCP       ToolSurface = "mcp"
	ToolSurfaceSkills    ToolSurface = "skills"
)

// ToolEventRouting keeps structured action evaluation separate from result
// content inspection and audit-only lifecycle handling. An event belongs to at
// most one route.
type ToolEventRouting struct {
	StructuredActionEvents []string `json:"structured_action_events"`
	ResultContentEvents    []string `json:"result_content_events"`
	StateTransitionEvents  []string `json:"state_transition_events"`
	AuditOnlyEvents        []string `json:"audit_only_events"`
}

// ToolEventRoute is the single evaluation path assigned to a hook event.
type ToolEventRoute string

const (
	ToolEventRouteUnknown          ToolEventRoute = "unknown"
	ToolEventRouteStructuredAction ToolEventRoute = "structured-action"
	ToolEventRouteResultContent    ToolEventRoute = "result-content"
	ToolEventRouteStateTransition  ToolEventRoute = "state-transition"
	ToolEventRouteAuditOnly        ToolEventRoute = "audit-only"
)

// ToolLifecycleOutcome is the authoritative outcome of one tool invocation.
// Unknown is fail-closed for state transitions: it may be audited but cannot
// commit a successful step.
type ToolLifecycleOutcome string

const (
	ToolLifecycleOutcomeUnknown   ToolLifecycleOutcome = "unknown"
	ToolLifecycleOutcomeSuccess   ToolLifecycleOutcome = "success"
	ToolLifecycleOutcomeFailure   ToolLifecycleOutcome = "failure"
	ToolLifecycleOutcomeDenied    ToolLifecycleOutcome = "denied"
	ToolLifecycleOutcomeCancelled ToolLifecycleOutcome = "cancelled"
)

// ToolCallLifecycleContract is the connector-specific trust boundary for the
// experimental stateful tool-call path.
//
// AuthoritativePendingDiscardEvents close only unresolved proposal scope at a
// documented turn or response boundary. AuthoritativeTerminalEvents close both
// pending and committed scope only at a documented session-end, deletion, or
// reset boundary. Neither kind of event implies that a pending tool succeeded.
// Payload-qualified events remain subject to the limitations listed by the
// contract.
type ToolCallLifecycleContract struct {
	Version                           int                          `json:"version"`
	PreProposalEvents                 []string                     `json:"pre_proposal_events"`
	AuthoritativeSuccessEvents        []string                     `json:"authoritative_success_events"`
	AuthoritativeFailureEvents        []string                     `json:"authoritative_failure_events"`
	AuthoritativeDenialEvents         []string                     `json:"authoritative_denial_events"`
	AuthoritativePendingDiscardEvents []string                     `json:"authoritative_pending_discard_events"`
	AuthoritativeTerminalEvents       []string                     `json:"authoritative_terminal_events"`
	InvocationIDAuthority             ToolInvocationIDAuthority    `json:"invocation_id_authority"`
	OutcomeAuthority                  ToolOutcomeAuthority         `json:"outcome_authority"`
	StatefulEnforcementLevel          StatefulToolEnforcementLevel `json:"stateful_enforcement_level"`
	Routing                           ToolEventRouting             `json:"routing"`
	CoveredToolSurfaces               []ToolSurface                `json:"covered_tool_surfaces"`
	OfficialSourceURLs                []string                     `json:"official_source_urls"`
	Limitations                       []string                     `json:"limitations"`
}

// RouteForEvent returns the contract-declared evaluation route. Event names
// are intentionally exact and versioned; case folding would silently widen a
// vendor contract.
func (contract ToolCallLifecycleContract) RouteForEvent(event string) ToolEventRoute {
	if containsExact(contract.Routing.StructuredActionEvents, event) {
		return ToolEventRouteStructuredAction
	}
	if containsExact(contract.Routing.ResultContentEvents, event) {
		return ToolEventRouteResultContent
	}
	if containsExact(contract.Routing.StateTransitionEvents, event) {
		return ToolEventRouteStateTransition
	}
	if containsExact(contract.Routing.AuditOnlyEvents, event) {
		return ToolEventRouteAuditOnly
	}
	return ToolEventRouteUnknown
}

// IsPreProposalEvent reports whether event can create a pending tool proposal.
func (contract ToolCallLifecycleContract) IsPreProposalEvent(event string) bool {
	return containsExact(contract.PreProposalEvents, event)
}

// IsStateTransitionEvent reports whether event is a connector-declared typed
// lifecycle state change. State-transition events are not tool proposals and
// must never create pending tool-invocation state.
func (contract ToolCallLifecycleContract) IsStateTransitionEvent(event string) bool {
	return containsExact(contract.Routing.StateTransitionEvents, event)
}

// IsAuthoritativeTerminalEvent reports whether event can close the exact
// authenticated session's pending and committed scope. It does not classify
// any pending invocation as successful.
func (contract ToolCallLifecycleContract) IsAuthoritativeTerminalEvent(event string) bool {
	return containsExact(contract.AuthoritativeTerminalEvents, event)
}

// IsAuthoritativePendingDiscardEvent reports whether event closes the current
// turn or response scope. It discards unfinished proposals but deliberately
// preserves successful predecessor history from earlier turns.
func (contract ToolCallLifecycleContract) IsAuthoritativePendingDiscardEvent(event string) bool {
	return containsExact(contract.AuthoritativePendingDiscardEvents, event)
}

// SupportsExactInvocationJoin reports whether the contract permits an opaque
// connector-owned per-call ID to drive enforcement state. Sequence/ordinal
// joins deliberately return false.
func (contract ToolCallLifecycleContract) SupportsExactInvocationJoin() bool {
	return contract.StatefulEnforcementLevel == StatefulToolPairedOutcomes &&
		contract.InvocationIDAuthority == ToolInvocationIDPairedID
}

// ExactInvocationJoinEligible further restricts exact joins to proposal and
// result events participating in this lifecycle contract.
func (contract ToolCallLifecycleContract) ExactInvocationJoinEligible(event string) bool {
	if !contract.SupportsExactInvocationJoin() {
		return false
	}
	return contract.IsPreProposalEvent(event) ||
		containsExact(contract.AuthoritativeSuccessEvents, event) ||
		containsExact(contract.AuthoritativeFailureEvents, event) ||
		containsExact(contract.AuthoritativeDenialEvents, event)
}

// ClassifyTerminalOutcome classifies only contract-declared authoritative
// outcome events. For result-payload contracts, missing or ambiguous status is
// unknown rather than optimistic success.
func (contract ToolCallLifecycleContract) ClassifyTerminalOutcome(
	connectorName string,
	event string,
	payload map[string]interface{},
) ToolLifecycleOutcome {
	wantsDenial := containsExact(contract.AuthoritativeDenialEvents, event)
	wantsSuccess := containsExact(contract.AuthoritativeSuccessEvents, event)
	wantsFailure := containsExact(contract.AuthoritativeFailureEvents, event)
	if !wantsDenial && !wantsSuccess && !wantsFailure {
		return ToolLifecycleOutcomeUnknown
	}

	if contract.OutcomeAuthority == ToolOutcomeEventKind {
		if wantsDenial {
			return ToolLifecycleOutcomeDenied
		}
		if wantsFailure && !wantsSuccess {
			return ToolLifecycleOutcomeFailure
		}
		if wantsSuccess && !wantsFailure {
			return ToolLifecycleOutcomeSuccess
		}
		return ToolLifecycleOutcomeUnknown
	}
	if contract.OutcomeAuthority == ToolOutcomeSurfaceSpecific {
		if normalizeConnectorName(connectorName) == "codex" {
			return classifyCodexResult(payload)
		}
		if wantsSuccess && !wantsFailure {
			return ToolLifecycleOutcomeSuccess
		}
		return ToolLifecycleOutcomeUnknown
	}
	if contract.OutcomeAuthority != ToolOutcomeResultPayload {
		return ToolLifecycleOutcomeUnknown
	}

	switch normalizeConnectorName(connectorName) {
	case "codex":
		return classifyCodexResult(payload)
	case "hermes":
		return classifyStatusValue(nestedValue(payload, "extra", "status"))
	case "geminicli":
		response, ok := nestedMap(payload, "tool_response", "toolResponse")
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		if errorValue, exists := firstPresent(response, "error"); exists && hasErrorValue(errorValue) {
			return classifyCancellationOrFailure(errorValue)
		}
		return ToolLifecycleOutcomeSuccess
	case "antigravity":
		if _, ok := firstPresent(payload, "stepIdx", "step_idx"); !ok {
			return ToolLifecycleOutcomeUnknown
		}
		if errorValue, exists := firstPresent(payload, "error"); exists && hasErrorValue(errorValue) {
			return classifyCancellationOrFailure(errorValue)
		}
		return ToolLifecycleOutcomeSuccess
	case "openhands":
		response, ok := nestedMap(payload, "tool_response", "toolResponse")
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		isError, ok := firstPresent(response, "is_error", "isError")
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		flag, ok := isError.(bool)
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		if flag {
			return ToolLifecycleOutcomeFailure
		}
		return ToolLifecycleOutcomeSuccess
	case "opencode":
		response, ok := nestedMap(payload, "tool_response", "toolResponse")
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		output, exists := firstPresent(response, "output")
		if !exists {
			return ToolLifecycleOutcomeUnknown
		}
		// OpenCode's reviewed after-hook result always owns a string output
		// field. The empty string is a valid result; a missing or differently
		// typed field is a malformed bridge payload and cannot prove success.
		if _, ok := output.(string); !ok {
			return ToolLifecycleOutcomeUnknown
		}
		toolNameValue, _ := firstPresent(payload, "tool_name", "toolName")
		toolName, _ := toolNameValue.(string)
		if strings.EqualFold(strings.TrimSpace(toolName), "bash") {
			metadata, ok := nestedMap(response, "metadata")
			if !ok {
				return ToolLifecycleOutcomeUnknown
			}
			exitValue, exists := firstPresent(metadata, "exit")
			exitCode, ok := numericInt64(exitValue)
			if !exists || !ok {
				return ToolLifecycleOutcomeUnknown
			}
			if exitCode != 0 {
				return ToolLifecycleOutcomeFailure
			}
		}
		return ToolLifecycleOutcomeSuccess
	case "amp":
		return classifyAmpResult(payload)
	default:
		return ToolLifecycleOutcomeUnknown
	}
}

func classifyAmpResult(payload map[string]interface{}) ToolLifecycleOutcome {
	statusValue, ok := firstPresent(payload, "status")
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}
	status, ok := statusValue.(string)
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}
	switch status {
	case "done":
		// Amp's result type does not permit an error on a completed tool. Treat
		// that contradictory shape as unknown instead of advancing state.
		if errorValue, exists := firstPresent(payload, "error"); exists && hasErrorValue(errorValue) {
			return ToolLifecycleOutcomeUnknown
		}
		return ToolLifecycleOutcomeSuccess
	case "error":
		return ToolLifecycleOutcomeFailure
	case "cancelled":
		return ToolLifecycleOutcomeCancelled
	default:
		return ToolLifecycleOutcomeUnknown
	}
}

func classifyCodexResult(payload map[string]interface{}) ToolLifecycleOutcome {
	toolName, ok := payload["tool_name"].(string)
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}

	// Codex apply_patch emits the reviewed canonical command field and a
	// scalar response only after the function finishes successfully. Keep the
	// exception exact: aliases and scalar shell/generic responses do not prove
	// an outcome.
	if toolName == "apply_patch" {
		toolInput, hasToolInput := payload["tool_input"].(map[string]interface{})
		_, hasCommand := toolInput["command"].(string)
		_, hasResponse := payload["tool_response"].(string)
		if hasToolInput && hasCommand && hasResponse {
			return ToolLifecycleOutcomeSuccess
		}
		return ToolLifecycleOutcomeUnknown
	}

	// MCP tools return an MCP CallToolResult. The content array establishes
	// that exact response shape; isError is optional and defaults to false in
	// the protocol. No other structured Codex response fields are outcome
	// authorities.
	if !strings.HasPrefix(toolName, "mcp__") {
		return ToolLifecycleOutcomeUnknown
	}
	if _, ok := payload["tool_input"].(map[string]interface{}); !ok {
		return ToolLifecycleOutcomeUnknown
	}
	response, ok := payload["tool_response"].(map[string]interface{})
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}
	if _, ok := response["content"].([]interface{}); !ok {
		return ToolLifecycleOutcomeUnknown
	}
	isError, exists := response["isError"]
	if !exists {
		return ToolLifecycleOutcomeSuccess
	}
	flag, ok := isError.(bool)
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}
	if flag {
		return ToolLifecycleOutcomeFailure
	}
	return ToolLifecycleOutcomeSuccess
}

func classifyStatusValue(value interface{}) ToolLifecycleOutcome {
	status, ok := value.(string)
	if !ok {
		return ToolLifecycleOutcomeUnknown
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok", "success", "succeeded", "completed":
		return ToolLifecycleOutcomeSuccess
	case "error", "failed", "failure":
		return ToolLifecycleOutcomeFailure
	case "blocked", "denied", "rejected", "permission_denied":
		return ToolLifecycleOutcomeDenied
	case "cancelled", "canceled", "aborted", "interrupted":
		return ToolLifecycleOutcomeCancelled
	default:
		return ToolLifecycleOutcomeUnknown
	}
}

func classifyCancellationOrFailure(value interface{}) ToolLifecycleOutcome {
	if text, ok := value.(string); ok {
		normalized := strings.ToLower(strings.TrimSpace(text))
		if strings.Contains(normalized, "cancel") || strings.Contains(normalized, "abort") || strings.Contains(normalized, "interrupt") {
			return ToolLifecycleOutcomeCancelled
		}
	}
	return ToolLifecycleOutcomeFailure
}

func hasErrorValue(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case bool:
		return typed
	default:
		return true
	}
}

func nestedMap(payload map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	value, ok := firstPresent(payload, keys...)
	if !ok {
		return nil, false
	}
	result, ok := value.(map[string]interface{})
	return result, ok
}

func nestedValue(payload map[string]interface{}, objectKey string, valueKey string) interface{} {
	object, ok := nestedMap(payload, objectKey)
	if !ok {
		return nil
	}
	value, _ := firstPresent(object, valueKey)
	return value
}

func firstPresent(payload map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, key := range keys {
		value, ok := payload[key]
		if ok {
			return value, true
		}
	}
	return nil, false
}

func numericInt64(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		converted := int64(typed)
		return converted, float64(converted) == typed
	default:
		return 0, false
	}
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func cloneToolCallLifecycleContract(in ToolCallLifecycleContract) ToolCallLifecycleContract {
	out := in
	out.PreProposalEvents = append([]string(nil), in.PreProposalEvents...)
	out.AuthoritativeSuccessEvents = append([]string(nil), in.AuthoritativeSuccessEvents...)
	out.AuthoritativeFailureEvents = append([]string(nil), in.AuthoritativeFailureEvents...)
	out.AuthoritativeDenialEvents = append([]string(nil), in.AuthoritativeDenialEvents...)
	out.AuthoritativePendingDiscardEvents = append([]string(nil), in.AuthoritativePendingDiscardEvents...)
	out.AuthoritativeTerminalEvents = append([]string(nil), in.AuthoritativeTerminalEvents...)
	out.Routing.StructuredActionEvents = append([]string(nil), in.Routing.StructuredActionEvents...)
	out.Routing.ResultContentEvents = append([]string(nil), in.Routing.ResultContentEvents...)
	out.Routing.StateTransitionEvents = append([]string(nil), in.Routing.StateTransitionEvents...)
	out.Routing.AuditOnlyEvents = append([]string(nil), in.Routing.AuditOnlyEvents...)
	out.CoveredToolSurfaces = append([]ToolSurface(nil), in.CoveredToolSurfaces...)
	out.OfficialSourceURLs = append([]string(nil), in.OfficialSourceURLs...)
	out.Limitations = append([]string(nil), in.Limitations...)
	return out
}

// ValidateToolCallLifecycleContract rejects incomplete or internally
// inconsistent trust declarations. supportedEvents must be the enclosing hook
// contract's event list.
func ValidateToolCallLifecycleContract(contract ToolCallLifecycleContract, supportedEvents []string) error {
	if contract.Version != ToolCallLifecycleContractVersion {
		return fmt.Errorf("tool-call lifecycle version %d is unsupported", contract.Version)
	}
	if !validInvocationIDAuthority(contract.InvocationIDAuthority) {
		return fmt.Errorf("unknown invocation ID authority %q", contract.InvocationIDAuthority)
	}
	if !validOutcomeAuthority(contract.OutcomeAuthority) {
		return fmt.Errorf("unknown outcome authority %q", contract.OutcomeAuthority)
	}
	if !validStatefulEnforcementLevel(contract.StatefulEnforcementLevel) {
		return fmt.Errorf("unknown stateful enforcement level %q", contract.StatefulEnforcementLevel)
	}
	if len(contract.PreProposalEvents) == 0 {
		return fmt.Errorf("pre-proposal events are required")
	}
	if len(contract.Routing.StructuredActionEvents) == 0 {
		return fmt.Errorf("structured-action routing is required")
	}
	if len(contract.CoveredToolSurfaces) == 0 {
		return fmt.Errorf("covered tool surfaces are required")
	}
	if len(contract.OfficialSourceURLs) == 0 || len(contract.Limitations) == 0 {
		return fmt.Errorf("official sources and limitations are required")
	}

	supported := stringSet(supportedEvents)
	structured := stringSet(contract.Routing.StructuredActionEvents)
	results := stringSet(contract.Routing.ResultContentEvents)
	transitions := stringSet(contract.Routing.StateTransitionEvents)
	audit := stringSet(contract.Routing.AuditOnlyEvents)
	for event := range structured {
		if results[event] || transitions[event] || audit[event] {
			return fmt.Errorf("event %q has more than one route", event)
		}
	}
	for event := range results {
		if transitions[event] || audit[event] {
			return fmt.Errorf("event %q has more than one route", event)
		}
	}
	for event := range transitions {
		if audit[event] {
			return fmt.Errorf("event %q has more than one route", event)
		}
	}
	for name, events := range map[string][]string{
		"pre-proposal":                  contract.PreProposalEvents,
		"authoritative-success":         contract.AuthoritativeSuccessEvents,
		"authoritative-failure":         contract.AuthoritativeFailureEvents,
		"authoritative-denial":          contract.AuthoritativeDenialEvents,
		"authoritative-pending-discard": contract.AuthoritativePendingDiscardEvents,
		"authoritative-terminal":        contract.AuthoritativeTerminalEvents,
		"structured-action":             contract.Routing.StructuredActionEvents,
		"result-content":                contract.Routing.ResultContentEvents,
		"state-transition":              contract.Routing.StateTransitionEvents,
		"audit-only":                    contract.Routing.AuditOnlyEvents,
	} {
		if err := validateUniqueEvents(name, events, supported); err != nil {
			return err
		}
	}
	for _, event := range contract.PreProposalEvents {
		if !structured[event] {
			return fmt.Errorf("pre-proposal event %q is not structured-action routed", event)
		}
	}
	for _, events := range [][]string{
		contract.AuthoritativeSuccessEvents,
		contract.AuthoritativeFailureEvents,
		contract.AuthoritativeDenialEvents,
	} {
		for _, event := range events {
			if !results[event] {
				return fmt.Errorf("authoritative outcome event %q is not result-content routed", event)
			}
		}
	}
	for _, event := range append(
		append([]string(nil), contract.AuthoritativePendingDiscardEvents...),
		contract.AuthoritativeTerminalEvents...,
	) {
		if !audit[event] {
			return fmt.Errorf("authoritative lifecycle boundary event %q is not audit-only routed", event)
		}
	}
	terminal := stringSet(contract.AuthoritativeTerminalEvents)
	for _, event := range contract.AuthoritativePendingDiscardEvents {
		if terminal[event] {
			return fmt.Errorf("event %q cannot discard pending state and reset the session", event)
		}
	}
	if contract.StatefulEnforcementLevel == StatefulToolPairedOutcomes &&
		(contract.InvocationIDAuthority != ToolInvocationIDPairedID || contract.OutcomeAuthority == ToolOutcomeNone) {
		return fmt.Errorf("paired-outcomes requires an exact paired ID and outcome authority")
	}
	if contract.OutcomeAuthority == ToolOutcomeNone &&
		(len(contract.AuthoritativeSuccessEvents) != 0 || len(contract.AuthoritativeFailureEvents) != 0) {
		return fmt.Errorf("outcome events require outcome authority")
	}

	seenSurfaces := make(map[ToolSurface]bool, len(contract.CoveredToolSurfaces))
	for _, surface := range contract.CoveredToolSurfaces {
		if !validToolSurface(surface) {
			return fmt.Errorf("unknown tool surface %q", surface)
		}
		if seenSurfaces[surface] {
			return fmt.Errorf("duplicate tool surface %q", surface)
		}
		seenSurfaces[surface] = true
	}
	for _, sourceURL := range contract.OfficialSourceURLs {
		if !strings.HasPrefix(sourceURL, "https://") {
			return fmt.Errorf("official source URL %q must use https", sourceURL)
		}
	}
	return nil
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func validateUniqueEvents(name string, events []string, supported map[string]bool) error {
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		if !supported[event] {
			return fmt.Errorf("%s event %q is not in the hook contract", name, event)
		}
		if seen[event] {
			return fmt.Errorf("duplicate %s event %q", name, event)
		}
		seen[event] = true
	}
	return nil
}

func validInvocationIDAuthority(value ToolInvocationIDAuthority) bool {
	switch value {
	case ToolInvocationIDNone, ToolInvocationIDPairedID, ToolInvocationIDPairedSequence:
		return true
	default:
		return false
	}
}

func validOutcomeAuthority(value ToolOutcomeAuthority) bool {
	switch value {
	case ToolOutcomeNone, ToolOutcomeEventKind, ToolOutcomeResultPayload, ToolOutcomeSurfaceSpecific:
		return true
	default:
		return false
	}
}

func validStatefulEnforcementLevel(value StatefulToolEnforcementLevel) bool {
	switch value {
	case StatefulToolDirectOnly, StatefulToolDetectionOnly, StatefulToolPairedOutcomes:
		return true
	default:
		return false
	}
}

func validToolSurface(value ToolSurface) bool {
	switch value {
	case ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead, ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP, ToolSurfaceSkills:
		return true
	default:
		return false
	}
}

func codexToolCallLifecycle(includeGeneric, includeSubagents, includeSessionEnd bool) ToolCallLifecycleContract {
	auditEvents := []string{"SessionStart", "Stop"}
	if includeSubagents {
		auditEvents = []string{"SessionStart", "SubagentStart", "SubagentStop", "Stop"}
	}
	terminalEvents := []string{}
	if includeSessionEnd {
		auditEvents = append(auditEvents, "SessionEnd")
		terminalEvents = []string{"SessionEnd"}
	}
	coveredSurfaces := []ToolSurface{
		ToolSurfaceShell, ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
	}
	if includeGeneric {
		coveredSurfaces = append([]ToolSurface{ToolSurfaceGeneric}, coveredSurfaces...)
	}
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{"PostToolUse"},
		AuthoritativeFailureEvents:        []string{"PostToolUse"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"Stop"},
		AuthoritativeTerminalEvents:       terminalEvents,
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeSurfaceSpecific,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse", "PermissionRequest"},
			ResultContentEvents:    []string{"PostToolUse"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        auditEvents,
		},
		CoveredToolSurfaces: coveredSurfaces,
		OfficialSourceURLs: []string{
			"https://learn.chatgpt.com/docs/hooks",
			"https://developers.openai.com/codex/config-reference/",
		},
		Limitations: []string{
			"PermissionRequest carries no tool_use_id, so it is a direct decision surface and can never create pending state.",
			"Only an exact apply_patch scalar response or an MCP CallToolResult with a content array and absent/false isError proves success; MCP isError=true proves failure.",
			"Shell and generic PostToolUse responses do not expose authoritative outcomes, and PostToolUse also fires for unsuccessful shell commands, so they never advance successful state.",
			"Hosted tools, file reads, and write_stdin do not provide complete hook coverage; skill loading has no dedicated tool-call lifecycle event.",
		},
	}
}

func claudeCodeToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{"PostToolUse"},
		AuthoritativeFailureEvents:        []string{"PostToolUseFailure"},
		AuthoritativeDenialEvents:         []string{"PermissionDenied"},
		AuthoritativePendingDiscardEvents: []string{"Stop", "StopFailure"},
		AuthoritativeTerminalEvents:       []string{"SessionEnd"},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeEventKind,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse", "PermissionRequest"},
			ResultContentEvents:    []string{"PostToolUse", "PostToolUseFailure", "PermissionDenied", "PostToolBatch"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"SessionStart", "Stop", "StopFailure", "SubagentStart", "SubagentStop", "SessionEnd"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://code.claude.com/docs/en/hooks",
			"https://code.claude.com/docs/en/tools-reference",
		},
		Limitations: []string{
			"PermissionRequest has no tool_use_id, so it is a direct decision surface and cannot create pending state.",
			"Direct slash-command skill invocation can bypass the Skill tool event; UserPromptExpansion remains the observable expansion boundary.",
			"File references expanded by the client are not equivalent to FileRead tool calls, and post-action hooks cannot undo completed side effects.",
		},
	}
}

func hermesToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"pre_tool_call"},
		AuthoritativeSuccessEvents:        []string{"post_tool_call"},
		AuthoritativeFailureEvents:        []string{"post_tool_call"},
		AuthoritativeDenialEvents:         []string{"post_tool_call"},
		AuthoritativePendingDiscardEvents: []string{},
		AuthoritativeTerminalEvents:       []string{"on_session_end", "on_session_finalize", "on_session_reset"},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"pre_tool_call"},
			ResultContentEvents:    []string{"post_tool_call"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents: []string{
				"on_session_start", "on_session_end", "on_session_finalize",
				"on_session_reset", "subagent_start", "subagent_stop",
			},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://github.com/NousResearch/hermes-agent/blob/126ff7071b6b755055879648f4e859b3187d0fac/agent/shell_hooks.py",
			"https://github.com/NousResearch/hermes-agent/blob/126ff7071b6b755055879648f4e859b3187d0fac/model_tools.py",
		},
		Limitations: []string{
			"Only pre_tool_call can block, and hook subprocess errors, timeouts, or malformed output fail open upstream.",
			"A post_tool_call commits success only when extra.status is ok; error and blocked statuses must not advance state.",
		},
	}
}

func cursorToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"preToolUse"},
		AuthoritativeSuccessEvents:        []string{"postToolUse"},
		AuthoritativeFailureEvents:        []string{"postToolUseFailure"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"stop"},
		AuthoritativeTerminalEvents:       []string{"sessionEnd"},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeEventKind,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{
				"preToolUse", "beforeShellExecution", "beforeMCPExecution",
				"beforeReadFile", "beforeTabFileRead",
			},
			ResultContentEvents: []string{
				"postToolUse", "postToolUseFailure", "afterShellExecution",
				"afterMCPExecution", "afterFileEdit", "afterTabFileEdit",
			},
			StateTransitionEvents: []string{},
			AuditOnlyEvents: []string{
				"sessionStart", "sessionEnd", "subagentStart", "subagentStop",
				"stop", "workspaceOpen",
			},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{
			"https://cursor.com/docs/hooks",
			"https://cursor.com/docs/skills",
		},
		Limitations: []string{
			"Only generic preToolUse/postToolUse events carry the stable tool_use_id used for stateful pairing; specialized shell, MCP, and file hooks are direct-evaluation or result-content surfaces.",
			"Hooks default to fail open unless failClosed is enabled, Tab has a separate partial hook surface, and cloud-agent hook coverage is not complete.",
		},
	}
}

func windsurfToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"},
		AuthoritativeSuccessEvents:        []string{"post_read_code", "post_write_code", "post_mcp_tool_use"},
		AuthoritativeFailureEvents:        []string{},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"post_cascade_response", "post_cascade_response_with_transcript"},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeSurfaceSpecific,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"},
			ResultContentEvents:    []string{"post_read_code", "post_write_code", "post_run_command", "post_mcp_tool_use"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"post_cascade_response", "post_cascade_response_with_transcript", "post_setup_worktree"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceShell, ToolSurfaceFileRead, ToolSurfaceFileWrite,
			ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{
			"https://docs.devin.ai/desktop/cascade/hooks",
			"https://docs.devin.ai/desktop/cascade/skills",
		},
		Limitations: []string{
			"Trajectory and execution identifiers are conversation/turn identifiers, not stable per-tool invocation IDs.",
			"post_run_command exposes neither an authoritative exit status nor output; hook errors other than exit code 2 fail open.",
		},
	}
}

func geminiCLIToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"BeforeTool"},
		AuthoritativeSuccessEvents:        []string{"AfterTool"},
		AuthoritativeFailureEvents:        []string{"AfterTool"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"AfterAgent"},
		AuthoritativeTerminalEvents:       []string{"SessionEnd"},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"BeforeTool"},
			ResultContentEvents:    []string{"AfterTool"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"SessionStart", "AfterAgent", "SessionEnd"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://geminicli.com/docs/hooks/reference/",
			"https://geminicli.com/docs/reference/tools/",
		},
		Limitations: []string{
			"Hook payloads provide a session identifier but no stable tool invocation identifier, so AfterTool cannot authorize a paired state transition.",
			"AfterTool is shared by success and failure; consumers must inspect tool_response.error instead of treating the event name as success.",
		},
	}
}

func copilotToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"preToolUse", "permissionRequest"},
		AuthoritativeSuccessEvents:        []string{"postToolUse"},
		AuthoritativeFailureEvents:        []string{"postToolUseFailure"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"agentStop"},
		AuthoritativeTerminalEvents:       []string{"sessionEnd"},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeEventKind,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"preToolUse", "permissionRequest"},
			ResultContentEvents:    []string{"postToolUse", "postToolUseFailure"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"sessionStart", "sessionEnd", "agentStop", "subagentStart", "subagentStop", "errorOccurred"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{
			"https://docs.github.com/en/copilot/reference/hooks-reference",
			"https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills",
		},
		Limitations: []string{
			"Hook payloads do not expose a per-tool invocation ID, and general-purpose subagents expose no reliable parent lineage.",
			"CLI hook timeouts and HTTP failures fail open; cloud agents expose only repository hooks, and skills have no invocation lifecycle event.",
		},
	}
}

func antigravityToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{"PostToolUse"},
		AuthoritativeFailureEvents:        []string{"PostToolUse"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"Stop"},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDPairedSequence,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse"},
			ResultContentEvents:    []string{"PostToolUse"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"PreInvocation", "PostInvocation", "Stop"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit,
		},
		OfficialSourceURLs: []string{
			"https://www.antigravity.google/docs/hooks",
			"https://github.com/google-antigravity/antigravity-cli/blob/21f650e7bb852f58562425ddd0c7d203c80e3d0e/CHANGELOG.md",
		},
		Limitations: []string{
			"conversationId plus stepIdx is a sequence rather than an opaque call ID, so it remains detection-only; CLI 1.1.9 or newer is required because it fixed spurious PostToolUse events and matcher handling.",
			"PreInvocation can inject context but cannot block or ask; Stop only supports continue, MCP hook matcher coverage is undocumented, and skill expansion has no dedicated event.",
		},
	}
}

func openHandsToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"pre_tool_use"},
		AuthoritativeSuccessEvents:        []string{"post_tool_use"},
		AuthoritativeFailureEvents:        []string{"post_tool_use"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"stop"},
		AuthoritativeTerminalEvents:       []string{"session_end"},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"pre_tool_use"},
			ResultContentEvents:    []string{"post_tool_use"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"session_start", "stop", "session_end"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://github.com/OpenHands/software-agent-sdk/blob/6d597ff7d5d3c89ef8ba0c8e3b3c6a09169da07c/openhands-sdk/openhands/sdk/hooks/types.py",
			"https://github.com/OpenHands/software-agent-sdk/blob/6d597ff7d5d3c89ef8ba0c8e3b3c6a09169da07c/openhands-sdk/openhands/sdk/hooks/conversation_hooks.py",
		},
		Limitations: []string{
			"Shell hook input omits the SDK's internal action ID, so PreToolUse and PostToolUse cannot be joined by an authoritative per-call identifier.",
			"Success requires tool_response.is_error=false; hook errors, timeouts, non-2 exits, and asynchronous PreToolUse hooks fail open.",
		},
	}
}

func openCodeToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"tool.execute.before"},
		AuthoritativeSuccessEvents:        []string{"tool.execute.after"},
		AuthoritativeFailureEvents:        []string{},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"session.idle"},
		AuthoritativeTerminalEvents:       []string{"session.deleted"},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"tool.execute.before"},
			ResultContentEvents:    []string{"tool.execute.after"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"session.created", "session.error", "session.idle", "session.deleted"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://github.com/anomalyco/opencode/blob/e4bd9757a3a5dc7461d286000a19e9bd7df57c40/packages/plugin/src/index.ts",
			"https://github.com/anomalyco/opencode/blob/e4bd9757a3a5dc7461d286000a19e9bd7df57c40/packages/opencode/src/session/tools.ts",
		},
		Limitations: []string{
			"Stateful success requires the v7 bridge, which forwards input.args plus the actual output and awaits delivery before returning to the agent.",
			"Exceptions can skip tool.execute.after, and delegated-task paths can emit it without a result; only a validated result payload is authoritative success. Bash additionally requires metadata.exit=0.",
		},
	}
}

func ampToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"tool.call"},
		AuthoritativeSuccessEvents:        []string{"tool.result"},
		AuthoritativeFailureEvents:        []string{"tool.result"},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"agent.end"},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"tool.call"},
			ResultContentEvents:    []string{"tool.result"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"session.start", "agent.start", "agent.end"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{
			"https://ampcode.com/manual/plugin-api",
			"https://registry.npmjs.org/@ampcode/plugin/-/plugin-0.0.0-20260729002615-g8a974c9.tgz",
		},
		Limitations: []string{
			"toolUseID is Amp's stable per-invocation join; tool.result status must be exactly done, error, or cancelled, and missing, contradictory, or unknown statuses never prove success.",
			"agent.end discards unfinished proposals for that turn but is not a documented session-end event; Amp exposes no terminal session or subagent-parent lifecycle boundary.",
			"tool.result gating can withhold or replace model-bound content but cannot undo completed tool side effects; skill invocation and remote Orb execution do not have separately certified lifecycle coverage.",
		},
	}
}

func omniGentToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{},
		AuthoritativeFailureEvents:        []string{},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"AfterAgentResponse"},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeNone,
		StatefulEnforcementLevel:          StatefulToolDirectOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse"},
			ResultContentEvents:    []string{"PostToolUse"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"AfterAgentResponse"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
			ToolSurfaceSkills,
		},
		OfficialSourceURLs: []string{
			"https://github.com/omnigent-ai/omnigent/blob/73657266ed68e50f30965a0202bc334f06507a30/omnigent/policies/schema.py",
			"https://omnigent.ai/docs/policies/custom",
		},
		Limitations: []string{
			"PolicyEvent exposes no call, session, conversation, or parent identifier; tool_result repeats request data but does not report authoritative success or failure.",
			"PostToolUse policy decisions can suppress or transform returned content but cannot undo side effects, so only direct pre-tool enforcement is enabled.",
		},
	}
}
