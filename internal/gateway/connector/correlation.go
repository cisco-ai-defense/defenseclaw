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
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxCorrelationProviderIDBytes = 512

// CorrelationProfileVersion is a closed identifier for a reviewed connector
// identity contract. A mapping change requires a new constant; silently
// changing an existing version would make persisted correlation evidence
// impossible to explain after an upgrade.
type CorrelationProfileVersion string

const (
	CorrelationProfileExplicitV1    CorrelationProfileVersion = "explicit-canonical-v1"
	CorrelationProfileOpenClawV1    CorrelationProfileVersion = "openclaw-correlation-v1"
	CorrelationProfileZeptoClawV1   CorrelationProfileVersion = "zeptoclaw-correlation-v1"
	CorrelationProfileClaudeCodeV1  CorrelationProfileVersion = "claudecode-correlation-v1"
	CorrelationProfileCodexV1       CorrelationProfileVersion = "codex-correlation-v1"
	CorrelationProfileHermesV1      CorrelationProfileVersion = "hermes-correlation-v1"
	CorrelationProfileCursorV1      CorrelationProfileVersion = "cursor-correlation-v1"
	CorrelationProfileWindsurfV1    CorrelationProfileVersion = "windsurf-correlation-v1"
	CorrelationProfileGeminiCLIV1   CorrelationProfileVersion = "geminicli-correlation-v1"
	CorrelationProfileCopilotV1     CorrelationProfileVersion = "copilot-correlation-v1"
	CorrelationProfileOpenHandsV1   CorrelationProfileVersion = "openhands-correlation-v1"
	CorrelationProfileAntigravityV1 CorrelationProfileVersion = "antigravity-correlation-v1"
	CorrelationProfileOpenCodeV1    CorrelationProfileVersion = "opencode-correlation-v1"
	CorrelationProfileOmniGentV1    CorrelationProfileVersion = "omnigent-correlation-v1"
)

// CorrelationOrigin describes how a canonical identity or relationship was
// obtained. Connector payload bindings in this file are always reported;
// later coordinator stages may mint or derive identities under an explicitly
// allowed rule.
type CorrelationOrigin string

const (
	CorrelationOriginReported   CorrelationOrigin = "reported"
	CorrelationOriginMinted     CorrelationOrigin = "defenseclaw_minted"
	CorrelationOriginDerived    CorrelationOrigin = "derived"
	CorrelationOriginInferred   CorrelationOrigin = "inferred"
	CorrelationOriginTraceExact CorrelationOrigin = "trace_exact"
)

// CorrelationCompletenessLevel is deliberately small and closed. "partial"
// means the connector exposes some facts for the dimension; "absent" means
// its reviewed contract exposes none. Missing reasons provide the detail.
type CorrelationCompletenessLevel string

const (
	CorrelationCompletenessComplete CorrelationCompletenessLevel = "complete"
	CorrelationCompletenessPartial  CorrelationCompletenessLevel = "partial"
	CorrelationCompletenessAbsent   CorrelationCompletenessLevel = "absent"
	CorrelationCompletenessUnknown  CorrelationCompletenessLevel = "unknown"
)

type CorrelationCompleteness struct {
	Session        CorrelationCompletenessLevel
	Turn           CorrelationCompletenessLevel
	AgentLifecycle CorrelationCompletenessLevel
	Tool           CorrelationCompletenessLevel
	Model          CorrelationCompletenessLevel
	NativeOTLP     CorrelationCompletenessLevel
	MissingReasons []string
}

// CorrelationSurface is the authenticated rail on which a binding applies.
// ConnectorInstanceID is intentionally absent: setup/authentication owns it,
// and no payload field may claim or override it.
type CorrelationSurface string

const (
	CorrelationSurfaceHook       CorrelationSurface = "hook"
	CorrelationSurfaceNativeOTLP CorrelationSurface = "native_otlp"
	CorrelationSurfaceProxy      CorrelationSurface = "proxy"
	CorrelationSurfaceStream     CorrelationSurface = "stream"
	CorrelationSurfaceInternal   CorrelationSurface = "internal"
)

type NativeTelemetryStability string

const (
	NativeTelemetryStable       NativeTelemetryStability = "stable"
	NativeTelemetryBeta         NativeTelemetryStability = "beta"
	NativeTelemetryExperimental NativeTelemetryStability = "experimental"
	NativeTelemetryNone         NativeTelemetryStability = "none"
)

type NativeTelemetrySignal string

const (
	NativeTelemetryLogs    NativeTelemetrySignal = "logs"
	NativeTelemetryTraces  NativeTelemetrySignal = "traces"
	NativeTelemetryMetrics NativeTelemetrySignal = "metrics"
)

// NativeTelemetrySpec records native-rail capability independently from hook
// decoding. Setup/custody code can therefore distinguish a supported native
// exporter from a hook-only connector without inferring capability from the
// presence of a config renderer.
type NativeTelemetrySpec struct {
	InputSurface        CorrelationSurface
	Signals             []NativeTelemetrySignal
	Stability           NativeTelemetryStability
	AcceptsW3C          bool
	PropagatesW3C       bool
	AuthoritativeFields []CorrelationTarget
}

// IsAuthoritative reports whether the reviewed native-telemetry contract
// permits target to prove identity across input rails. Native bindings that
// are not authoritative are still retained as typed evidence and projected to
// canonical records; they cannot collapse two semantic occurrences.
func (s NativeTelemetrySpec) IsAuthoritative(target CorrelationTarget) bool {
	for _, candidate := range s.AuthoritativeFields {
		if candidate == target {
			return true
		}
	}
	return false
}

// CorrelationTarget is the closed set of identity meanings a connector may
// bind. Values from different targets are never compared as interchangeable.
type CorrelationTarget string

const (
	CorrelationTargetSemanticEvent CorrelationTarget = "semantic_event"
	CorrelationTargetSession       CorrelationTarget = "session"
	CorrelationTargetThread        CorrelationTarget = "thread"
	CorrelationTargetTurn          CorrelationTarget = "turn"
	CorrelationTargetMessage       CorrelationTarget = "message"
	CorrelationTargetAgent         CorrelationTarget = "agent"
	CorrelationTargetAgentName     CorrelationTarget = "agent_name"
	CorrelationTargetAgentType     CorrelationTarget = "agent_type"
	CorrelationTargetRootAgent     CorrelationTarget = "root_agent"
	CorrelationTargetParentAgent   CorrelationTarget = "parent_agent"
	CorrelationTargetChildAgent    CorrelationTarget = "child_agent"
	CorrelationTargetRootSession   CorrelationTarget = "root_session"
	CorrelationTargetParentSession CorrelationTarget = "parent_session"
	CorrelationTargetChildSession  CorrelationTarget = "child_session"
	CorrelationTargetTool          CorrelationTarget = "tool_invocation"
	CorrelationTargetModelRequest  CorrelationTarget = "model_request"
	CorrelationTargetModelResponse CorrelationTarget = "model_response"
	CorrelationTargetAction        CorrelationTarget = "action"
	CorrelationTargetSourceEvent   CorrelationTarget = "source_event"
	CorrelationTargetSourceSeq     CorrelationTarget = "source_sequence"
	CorrelationTargetSourceTime    CorrelationTarget = "source_timestamp"
	CorrelationTargetExecution     CorrelationTarget = "execution"
	CorrelationTargetStep          CorrelationTarget = "step"
)

// CorrelationInferenceRule is an allow-list, never a request from the
// connector. The coordinator may apply only rules declared by the resolved
// profile version.
type CorrelationInferenceRule string

const (
	CorrelationInferencePromptBoundaryTurn CorrelationInferenceRule = "mint_turn_at_prompt_boundary"
	CorrelationInferenceModelBoundary      CorrelationInferenceRule = "mint_model_request_at_model_boundary"
	CorrelationInferenceSubagentIdentity   CorrelationInferenceRule = "derive_subagent_identity"
	CorrelationInferenceUniquePendingTool  CorrelationInferenceRule = "unique_pending_tool"
	CorrelationInferenceTraceLink          CorrelationInferenceRule = "w3c_trace_link"
)

type CorrelationLifecycle string

const (
	CorrelationLifecycleSessionStart  CorrelationLifecycle = "session_start"
	CorrelationLifecycleSessionEnd    CorrelationLifecycle = "session_end"
	CorrelationLifecycleTurnStart     CorrelationLifecycle = "turn_start"
	CorrelationLifecycleTurnEnd       CorrelationLifecycle = "turn_end"
	CorrelationLifecycleToolStart     CorrelationLifecycle = "tool_start"
	CorrelationLifecycleToolEnd       CorrelationLifecycle = "tool_end"
	CorrelationLifecycleModelStart    CorrelationLifecycle = "model_start"
	CorrelationLifecycleModelEnd      CorrelationLifecycle = "model_end"
	CorrelationLifecycleSubagentStart CorrelationLifecycle = "subagent_start"
	CorrelationLifecycleSubagentEnd   CorrelationLifecycle = "subagent_end"
)

type CorrelationLifecycleBinding struct {
	Lifecycle CorrelationLifecycle
	Events    []string
}

// CorrelationFieldBinding maps reviewed connector paths to one exact meaning.
// Paths are ordered and may contain one declared nested object (for example
// "extra.child_session_id"). Namespace and IDKind are persisted alongside a
// source ID so receipts are scoped by connector instance + namespace + kind.
type CorrelationFieldBinding struct {
	Target    CorrelationTarget
	Paths     []string
	Origin    CorrelationOrigin
	Namespace string
	IDKind    string
}

// CorrelationPathAlias records a provider-documented case where one native
// value has two meanings in that provider's model. Matching still keys on the
// target/kind, so declaring an alias never makes different ID kinds equal.
type CorrelationPathAlias struct {
	Path    string
	Targets []CorrelationTarget
}

type CorrelationValue struct {
	Target    CorrelationTarget
	Value     string
	Path      string
	Origin    CorrelationOrigin
	Namespace string
	IDKind    string
}

// CorrelationContractSource pins the immutable provider material reviewed for
// one correlation profile. Git-backed sources use a full commit hash; rendered
// documentation uses a sha256:<hex> content digest. A profile mapping must be
// versioned again whenever any pinned source or field interpretation changes.
type CorrelationContractSource struct {
	ID          string
	URI         string
	Revision    string
	CheckedDate string
	Fixtures    []CorrelationContractFixture
}

// CorrelationContractFixture identifies source-shaped bytes checked into this
// repository. EvidenceKind distinguishes a provider capture from a fixture
// derived directly from an immutable provider source contract; callers must
// never represent a derived fixture as a live capture.
type CorrelationContractFixture struct {
	ID           string
	Surface      CorrelationSurface
	Path         string
	SHA256       string
	AgentVersion string
	EvidenceKind string
}

// CorrelationFieldEvidence is the field-level authority gate. Bindings without
// evidence remain useful typed facts, but cannot collapse hook and native OTLP
// occurrences. MirrorProofID joins only source-backed spellings proven to name
// the same provider occurrence across two rails.
type CorrelationFieldEvidence struct {
	SourceID      string
	FixtureID     string
	Surface       CorrelationSurface
	Target        CorrelationTarget
	Path          string
	Authoritative bool
	MirrorProofID string
}

// CorrelationSpec is the versioned normalization contract for one connector.
// HookBindings and NativeOTLPBindings are separate because an attribute name
// documented on native OTLP must never become a hook-payload alias by accident.
type CorrelationSpec struct {
	Connector           string
	ProfileVersion      CorrelationProfileVersion
	HookContractID      string
	MinAgentVersion     string
	MaxAgentVersion     string
	CompatibilityStatus string
	Surfaces            []CorrelationSurface
	HookBindings        []CorrelationFieldBinding
	ProxyBindings       []CorrelationFieldBinding
	StreamBindings      []CorrelationFieldBinding
	NativeOTLPBindings  []CorrelationFieldBinding
	NativeTelemetry     NativeTelemetrySpec
	ContractSources     []CorrelationContractSource
	FieldEvidence       []CorrelationFieldEvidence
	DeclaredPathAliases []CorrelationPathAlias
	Lifecycle           []CorrelationLifecycleBinding
	// ReceiptTargets are provider-declared occurrence IDs eligible for exact
	// replay suppression. MirrorIdentityTargets are occurrence-level IDs that
	// may prove same-phase hook/native equivalence; membership IDs such as
	// session, thread and turn are intentionally excluded.
	ReceiptTargets        []CorrelationTarget
	MirrorIdentityTargets []CorrelationTarget
	AllowedInferenceRules []CorrelationInferenceRule
	SupportsTraceparent   bool
	Completeness          CorrelationCompleteness
}

type CorrelationSpecProvider interface {
	CorrelationSpec(opts SetupOpts) CorrelationSpec
}

func reported(target CorrelationTarget, namespace, kind string, paths ...string) CorrelationFieldBinding {
	return CorrelationFieldBinding{Target: target, Paths: paths, Origin: CorrelationOriginReported, Namespace: namespace, IDKind: kind}
}

func commonCanonicalBindings(namespace string) []CorrelationFieldBinding {
	// These exact keys are the only payload identities accepted for an
	// unknown/plugin connector without a supplied profile. Vendor aliases such
	// as conversation_id, task_id, execution_id, generation_id and step_id are
	// intentionally absent.
	return []CorrelationFieldBinding{
		reported(CorrelationTargetSemanticEvent, "defenseclaw", "semantic_event", "defenseclaw.semantic_event.id"),
		reported(CorrelationTargetSession, namespace, "session", "session_id"),
		reported(CorrelationTargetTurn, namespace, "turn", "turn_id"),
		reported(CorrelationTargetMessage, namespace, "message", "message_id"),
		reported(CorrelationTargetAgent, namespace, "agent", "agent_id"),
		reported(CorrelationTargetAgentName, namespace, "agent_name", "agent_name"),
		reported(CorrelationTargetAgentType, namespace, "agent_type", "agent_type"),
		reported(CorrelationTargetRootAgent, namespace, "root_agent", "root_agent_id"),
		reported(CorrelationTargetParentAgent, namespace, "parent_agent", "parent_agent_id"),
		reported(CorrelationTargetChildAgent, namespace, "child_agent", "child_agent_id"),
		reported(CorrelationTargetRootSession, namespace, "root_session", "root_session_id"),
		reported(CorrelationTargetParentSession, namespace, "parent_session", "parent_session_id"),
		reported(CorrelationTargetChildSession, namespace, "child_session", "child_session_id"),
		reported(CorrelationTargetTool, namespace, "tool_invocation", "tool_call_id"),
		reported(CorrelationTargetModelRequest, namespace, "model_request", "model_request_id"),
		reported(CorrelationTargetModelResponse, namespace, "model_response", "model_response_id"),
		reported(CorrelationTargetSourceEvent, namespace, "source_event", "source_event_id"),
		reported(CorrelationTargetSourceSeq, namespace, "source_sequence", "source_sequence"),
		reported(CorrelationTargetSourceTime, namespace, "source_timestamp", "source_timestamp"),
	}
}

// ExplicitCanonicalCorrelationSpec is the fail-closed profile for an unknown
// connector. It accepts only exact canonical hook fields and declares no
// inference or completeness claims.
func ExplicitCanonicalCorrelationSpec(connectorName string) CorrelationSpec {
	connectorName = strings.TrimSpace(connectorName)
	return CorrelationSpec{
		Connector: connectorName, ProfileVersion: CorrelationProfileExplicitV1,
		CompatibilityStatus: HookCompatibilityUnknown,
		Surfaces:            []CorrelationSurface{CorrelationSurfaceHook},
		HookBindings:        commonCanonicalBindings(connectorName),
		ContractSources:     correlationContractSources("explicit"),
		// An unknown/plugin connector still gets exact replay protection when
		// it explicitly supplies the canonical source_event_id field. No vendor
		// alias or contextual inference is enabled by this declaration.
		ReceiptTargets:  []CorrelationTarget{CorrelationTargetSourceEvent},
		NativeTelemetry: NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Stability: NativeTelemetryNone},
		Completeness: CorrelationCompleteness{
			Session: CorrelationCompletenessUnknown, Turn: CorrelationCompletenessUnknown,
			AgentLifecycle: CorrelationCompletenessUnknown, Tool: CorrelationCompletenessUnknown,
			Model: CorrelationCompletenessUnknown, NativeOTLP: CorrelationCompletenessUnknown,
			MissingReasons: []string{"connector has no resolved versioned correlation profile"},
		},
	}
}

func appendBindings(base []CorrelationFieldBinding, extra ...CorrelationFieldBinding) []CorrelationFieldBinding {
	overrides := make(map[string]bool)
	for _, binding := range extra {
		for _, path := range binding.Paths {
			overrides[path] = true
		}
	}
	out := make([]CorrelationFieldBinding, 0, len(base)+len(extra))
	for _, binding := range base {
		copyBinding := binding
		copyBinding.Paths = make([]string, 0, len(binding.Paths))
		for _, path := range binding.Paths {
			if overrides[path] {
				continue
			}
			copyBinding.Paths = append(copyBinding.Paths, path)
		}
		if len(copyBinding.Paths) != 0 {
			out = append(out, copyBinding)
		}
	}
	return append(out, extra...)
}

func declaredCorrelationAliases(name string) []CorrelationPathAlias {
	switch name {
	case "openclaw":
		// One session.message frame's message ID is both the provider's
		// message identity and the exact source occurrence for that frame. It
		// remains distinct from the DefenseClaw-minted turn identity.
		return []CorrelationPathAlias{
			{Path: "messageId", Targets: []CorrelationTarget{CorrelationTargetMessage, CorrelationTargetSourceEvent}},
			{Path: "message_id", Targets: []CorrelationTarget{CorrelationTargetMessage, CorrelationTargetSourceEvent}},
		}
	case "hermes":
		return []CorrelationPathAlias{{Path: "extra.child_role", Targets: []CorrelationTarget{CorrelationTargetAgentName, CorrelationTargetAgentType}}}
	case "windsurf":
		return []CorrelationPathAlias{
			{Path: "execution_id", Targets: []CorrelationTarget{CorrelationTargetTurn, CorrelationTargetExecution}},
			{Path: "executionId", Targets: []CorrelationTarget{CorrelationTargetTurn, CorrelationTargetExecution}},
		}
	default:
		return nil
	}
}

func correlationLifecycleForContract(contract HookContract) []CorrelationLifecycleBinding {
	if contract.ContractID == "" {
		return nil
	}
	declared := make(map[string]bool, len(contract.Events))
	for _, event := range contract.Events {
		declared[event] = true
	}
	candidates := []CorrelationLifecycleBinding{
		{Lifecycle: CorrelationLifecycleSessionStart, Events: []string{
			"SessionStart", "sessionStart", "session_start", "session.created", "on_session_start",
		}},
		{Lifecycle: CorrelationLifecycleSessionEnd, Events: []string{
			"SessionEnd", "sessionEnd", "session_end", "session.deleted", "on_session_end", "on_session_finalize",
		}},
		{Lifecycle: CorrelationLifecycleTurnStart, Events: []string{
			"UserPromptSubmit", "userPromptSubmitted", "user_prompt_submit", "beforeSubmitPrompt",
			"BeforeAgent", "PreInvocation", "pre_user_prompt", "pre_llm_call",
		}},
		{Lifecycle: CorrelationLifecycleTurnEnd, Events: []string{
			"Stop", "stop", "agentStop", "AfterAgent", "AfterAgentResponse", "PostInvocation",
			"afterAgentResponse", "post_cascade_response", "post_cascade_response_with_transcript", "post_llm_call",
		}},
		{Lifecycle: CorrelationLifecycleToolStart, Events: []string{
			"PreToolUse", "preToolUse", "pre_tool_use", "BeforeTool", "pre_tool_call",
			"pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use",
			"beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeTabFileRead",
			"tool.execute.before",
		}},
		{Lifecycle: CorrelationLifecycleToolEnd, Events: []string{
			"PostToolUse", "postToolUse", "post_tool_use", "PostToolUseFailure", "postToolUseFailure",
			"AfterTool", "post_tool_call", "post_read_code", "post_write_code", "post_run_command",
			"post_mcp_tool_use", "afterShellExecution", "afterMCPExecution", "afterFileEdit",
			"afterTabFileEdit", "tool.execute.after",
		}},
		{Lifecycle: CorrelationLifecycleModelStart, Events: []string{
			"BeforeModel",
		}},
		{Lifecycle: CorrelationLifecycleModelEnd, Events: []string{
			"AfterModel",
		}},
		{Lifecycle: CorrelationLifecycleSubagentStart, Events: []string{
			"SubagentStart", "subagentStart", "subagent_start",
		}},
		{Lifecycle: CorrelationLifecycleSubagentEnd, Events: []string{
			"SubagentStop", "subagentStop", "subagent_stop",
		}},
	}
	result := make([]CorrelationLifecycleBinding, 0, len(candidates))
	for _, candidate := range candidates {
		filtered := make([]string, 0, len(candidate.Events))
		for _, event := range candidate.Events {
			if declared[event] {
				filtered = append(filtered, event)
			}
		}
		if len(filtered) != 0 {
			candidate.Events = filtered
			result = append(result, candidate)
		}
	}
	return result
}

func nativeStandard(namespace string) []CorrelationFieldBinding {
	return []CorrelationFieldBinding{
		reported(CorrelationTargetSemanticEvent, "defenseclaw", "semantic_event", "defenseclaw.semantic_event.id"),
		reported(CorrelationTargetSession, namespace, "session", "gen_ai.conversation.id"),
		reported(CorrelationTargetTurn, namespace, "turn", "defenseclaw.turn.id"),
		reported(CorrelationTargetAgent, namespace, "agent", "gen_ai.agent.id"),
		reported(CorrelationTargetModelRequest, namespace, "model_request", "defenseclaw.model.request.id"),
		reported(CorrelationTargetModelResponse, namespace, "model_response", "gen_ai.response.id", "defenseclaw.model.response.id"),
		reported(CorrelationTargetTool, namespace, "tool_invocation", "gen_ai.tool.call.id", "defenseclaw.tool.invocation.id"),
	}
}

func nativeTelemetryForConnector(name string) NativeTelemetrySpec {
	none := NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Stability: NativeTelemetryNone}
	switch name {
	case "codex":
		// Only call_id is source-proven to be the same invocation exported to
		// Codex hooks as tool_use_id. Standard GenAI attributes remain typed
		// native evidence, but are not cross-rail identity authority by default.
		return NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Signals: []NativeTelemetrySignal{NativeTelemetryLogs, NativeTelemetryTraces, NativeTelemetryMetrics}, Stability: NativeTelemetryStable, AcceptsW3C: true, PropagatesW3C: true, AuthoritativeFields: []CorrelationTarget{CorrelationTargetTool}}
	case "claudecode":
		// Official monitoring documentation states that native tool_use_id and
		// gen_ai.tool.call.id carry the same value passed to hooks.
		return NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Signals: []NativeTelemetrySignal{NativeTelemetryLogs, NativeTelemetryMetrics, NativeTelemetryTraces}, Stability: NativeTelemetryBeta, AcceptsW3C: true, PropagatesW3C: true, AuthoritativeFields: []CorrelationTarget{CorrelationTargetTool}}
	case "geminicli":
		return NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Signals: []NativeTelemetrySignal{NativeTelemetryLogs, NativeTelemetryTraces, NativeTelemetryMetrics}, Stability: NativeTelemetryStable, AcceptsW3C: true, PropagatesW3C: true}
	case "copilot":
		return NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Signals: []NativeTelemetrySignal{NativeTelemetryLogs, NativeTelemetryTraces, NativeTelemetryMetrics}, Stability: NativeTelemetryStable, AcceptsW3C: true, PropagatesW3C: true}
	case "omnigent":
		return NativeTelemetrySpec{InputSurface: CorrelationSurfaceNativeOTLP, Signals: []NativeTelemetrySignal{NativeTelemetryLogs, NativeTelemetryTraces, NativeTelemetryMetrics}, Stability: NativeTelemetryExperimental, AcceptsW3C: true, PropagatesW3C: true}
	default:
		return none
	}
}

func mirrorIdentityTargets(name string) []CorrelationTarget {
	switch name {
	case "codex":
		return []CorrelationTarget{CorrelationTargetTool}
	case "claudecode":
		return []CorrelationTarget{CorrelationTargetTool}
	default:
		return nil
	}
}

// CorrelationSpecForConnector returns a fresh copy of a built-in profile.
// hookContractID is mandatory for hook connectors so mappings cannot outlive
// the hook schema version they were reviewed against. Proxy connectors use an
// empty contract ID because their wire versioning is not HookContract based.
func CorrelationSpecForConnector(name, hookContractID string) (CorrelationSpec, bool) {
	name = normalizeConnectorName(name)
	ns := name
	base := commonCanonicalBindings(ns)
	complete := func(session, turn, agent, tool, model, native CorrelationCompletenessLevel, reasons ...string) CorrelationCompleteness {
		return CorrelationCompleteness{Session: session, Turn: turn, AgentLifecycle: agent, Tool: tool, Model: model, NativeOTLP: native, MissingReasons: reasons}
	}
	makeSpec := func(version CorrelationProfileVersion, contractID string, surfaces []CorrelationSurface, bindings, native []CorrelationFieldBinding, inference []CorrelationInferenceRule, completeness CorrelationCompleteness) (CorrelationSpec, bool) {
		if contractID != "" && hookContractID != contractID {
			return CorrelationSpec{}, false
		}
		nativeSpec := nativeTelemetryForConnector(name)
		contract, hasContract := hookContractByID(name, contractID)
		if contractID != "" && !hasContract {
			return CorrelationSpec{}, false
		}
		compatibility := HookCompatibilityNotGated
		if hasContract {
			compatibility = HookCompatibilityKnown
		}
		return CorrelationSpec{
			Connector: name, ProfileVersion: version, HookContractID: contractID,
			MinAgentVersion: contract.MinAgentVersion, MaxAgentVersion: contract.MaxAgentVersion,
			CompatibilityStatus: compatibility,
			Surfaces:            surfaces, HookBindings: append([]CorrelationFieldBinding(nil), bindings...),
			NativeOTLPBindings:    append([]CorrelationFieldBinding(nil), native...),
			NativeTelemetry:       nativeSpec,
			ContractSources:       correlationContractSources(name),
			FieldEvidence:         correlationFieldEvidence(name),
			DeclaredPathAliases:   declaredCorrelationAliases(name),
			Lifecycle:             correlationLifecycleForContract(contract),
			ReceiptTargets:        []CorrelationTarget{CorrelationTargetSourceEvent},
			MirrorIdentityTargets: mirrorIdentityTargets(name),
			AllowedInferenceRules: append([]CorrelationInferenceRule(nil), inference...),
			SupportsTraceparent:   contract.SupportsTraceparent || nativeSpec.AcceptsW3C || nativeSpec.PropagatesW3C,
			Completeness:          completeness,
		}, true
	}

	switch name {
	case "openclaw":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "session", "sessionKey", "session_key"),
			reported(CorrelationTargetMessage, ns, "message", "messageId", "message_id"),
			reported(CorrelationTargetExecution, ns, "agent_run", "runId", "run_id"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "callId", "call_id", "toolCallId"),
			reported(CorrelationTargetSourceSeq, ns, "source_sequence", "sequence", "seq"),
		)
		spec, ok := makeSpec(CorrelationProfileOpenClawV1, "", []CorrelationSurface{CorrelationSurfaceProxy, CorrelationSurfaceStream}, bindings, nil, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessAbsent, "upstream parent/depth fields are not retained on every EventRouter event", "no reviewed customer native OTLP contract"))
		if ok {
			spec.ProxyBindings = []CorrelationFieldBinding{
				reported(CorrelationTargetSession, ns, "session", "session_id"),
				reported(CorrelationTargetModelResponse, ns, "model_response", "response_id"),
				reported(CorrelationTargetTool, ns, "tool_invocation", "tool_call_id"),
			}
			spec.StreamBindings = []CorrelationFieldBinding{
				reported(CorrelationTargetSession, ns, "session", "sessionKey", "session_key"),
				reported(CorrelationTargetMessage, ns, "message", "messageId", "message_id"),
				reported(CorrelationTargetSourceEvent, ns, "message_event", "messageId", "message_id"),
				reported(CorrelationTargetExecution, ns, "agent_run", "runId", "run_id"),
				reported(CorrelationTargetTool, ns, "tool_invocation", "callId", "call_id", "toolCallId"),
				reported(CorrelationTargetSourceSeq, ns, "source_sequence", "sequence", "seq"),
			}
		}
		return spec, ok
	case "zeptoclaw":
		bindings := appendBindings(base,
			reported(CorrelationTargetModelRequest, ns, "provider_request", "provider_request_id"),
			reported(CorrelationTargetModelResponse, ns, "provider_response", "provider_response_id", "response_id"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "provider_tool_call_id"),
		)
		spec, ok := makeSpec(CorrelationProfileZeptoClawV1, "", []CorrelationSurface{CorrelationSurfaceProxy}, bindings, nil, []CorrelationInferenceRule{CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessAbsent, CorrelationCompletenessAbsent, CorrelationCompletenessAbsent, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessAbsent, "proxy integration does not receive ZeptoClaw session or agent lifecycle IDs"))
		if ok {
			spec.ProxyBindings = []CorrelationFieldBinding{
				reported(CorrelationTargetModelRequest, ns, "provider_request", "provider_request_id"),
				reported(CorrelationTargetModelResponse, ns, "provider_response", "provider_response_id"),
				reported(CorrelationTargetTool, ns, "tool_invocation", "provider_tool_call_id"),
			}
		}
		return spec, ok
	case "codex":
		bindings := appendBindings(base,
			reported(CorrelationTargetThread, ns, "thread", "thread_id", "threadId"),
			reported(CorrelationTargetSession, ns, "session", "sessionId"),
			reported(CorrelationTargetTurn, ns, "turn", "turnId", "codex.turn.id"),
			reported(CorrelationTargetSourceEvent, ns, "item", "item_id", "itemId"),
			// Codex source revision f90e7de emits one invocation call_id to
			// native codex.tool_result telemetry and forwards that same value to
			// hooks as tool_use_id. Other generic tool spellings remain typed
			// fallbacks and never receive mirror authority.
			reported(CorrelationTargetTool, ns, "tool_invocation", "tool_use_id"),
			reported(CorrelationTargetModelRequest, ns, "provider_request", "request_id", "requestId"),
			reported(CorrelationTargetSourceEvent, ns, "hook_event", "event_id", "eventId", "hook_event_id"),
		)
		native := appendBindings(nativeStandard(ns),
			reported(CorrelationTargetSession, ns, "session", "conversation.id"),
			reported(CorrelationTargetThread, ns, "thread", "thread.id", "codex.thread.id"),
			reported(CorrelationTargetTurn, ns, "turn", "codex.turn.id", "turn.id"),
			reported(CorrelationTargetSourceEvent, ns, "item", "item.id", "codex.item.id"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "call_id"),
		)
		return makeSpec(CorrelationProfileCodexV1, "codex-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook, CorrelationSurfaceNativeOTLP}, bindings, native, []CorrelationInferenceRule{CorrelationInferenceUniquePendingTool, CorrelationInferenceTraceLink}, complete(CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, "Codex hooks do not report stable parent/depth lineage or a provider response ID"))
	case "claudecode":
		bindings := appendBindings(base,
			reported(CorrelationTargetTurn, ns, "prompt", "prompt_id"),
			reported(CorrelationTargetAgent, ns, "agent", "agentId"),
			reported(CorrelationTargetChildAgent, ns, "subagent", "subagent_id", "subagentId", "child_agent_id", "childAgentId"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "tool_use_id", "toolUseId"),
		)
		native := appendBindings(nativeStandard(ns),
			reported(CorrelationTargetSession, ns, "session", "session.id"),
			reported(CorrelationTargetTurn, ns, "prompt", "prompt.id"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "tool_use_id"),
			reported(CorrelationTargetModelRequest, ns, "client_request", "client_request_id"),
			reported(CorrelationTargetModelResponse, ns, "model_response", "request_id"),
		)
		spec, ok := makeSpec(CorrelationProfileClaudeCodeV1, "claudecode-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook, CorrelationSurfaceNativeOTLP}, bindings, native, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceSubagentIdentity, CorrelationInferenceUniquePendingTool, CorrelationInferenceTraceLink}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, "prompt_id is available in Claude Code 2.1.196 and later; hook events do not report provider request/response IDs"))
		if ok {
			// prompt_id is the exact hook/native turn anchor, but it was added
			// after the broader v1 hook contract. Record the narrower reviewed
			// correlation floor without changing the hook installation contract.
			spec.MinAgentVersion = "2.1.196"
		}
		return spec, ok
	case "hermes":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "session", "extra.session_id"),
			reported(CorrelationTargetTurn, ns, "turn", "extra.turn_id"),
			reported(CorrelationTargetAgent, ns, "agent", "extra.agent_id", "extra.subagent_id"),
			reported(CorrelationTargetAgentName, ns, "agent_name", "extra.agent_name", "extra.child_role"),
			reported(CorrelationTargetAgentType, ns, "agent_type", "extra.agent_type", "extra.child_role"),
			reported(CorrelationTargetRootAgent, ns, "root_agent", "extra.root_agent_id"),
			reported(CorrelationTargetParentAgent, ns, "parent_agent", "extra.parent_subagent_id", "extra.parent_agent_id"),
			reported(CorrelationTargetChildAgent, ns, "child_agent", "extra.child_subagent_id", "extra.child_agent_id"),
			reported(CorrelationTargetRootSession, ns, "root_session", "extra.root_session_id"),
			reported(CorrelationTargetParentSession, ns, "parent_session", "extra.parent_session_id"),
			reported(CorrelationTargetChildSession, ns, "child_session", "extra.child_session_id"),
			reported(CorrelationTargetTool, ns, "tool_call", "extra.tool_call_id", "extra.tool_use_id"),
			reported(CorrelationTargetExecution, ns, "observer_api_operation", "extra.api_request_id"),
			reported(CorrelationTargetSourceEvent, ns, "observer_event", "extra.event_id", "extra.observer_event_id"),
			reported(CorrelationTargetSourceSeq, ns, "observer_sequence", "extra.sequence", "extra.seq"),
		)
		return makeSpec(CorrelationProfileHermesV1, "hermes-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceSubagentIdentity, CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, "legacy shell events may omit turn identity"))
	case "cursor":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "conversation", "conversation_id", "conversationId"),
			reported(CorrelationTargetTurn, ns, "generation", "generation_id", "generationId"),
			reported(CorrelationTargetSourceEvent, ns, "message", "messageId"),
			reported(CorrelationTargetTool, ns, "tool_use", "tool_use_id", "toolUseId", "toolCallId"),
			reported(CorrelationTargetChildAgent, ns, "subagent", "subagent_id", "subagentId"),
		)
		return makeSpec(CorrelationProfileCursorV1, "cursor-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferenceSubagentIdentity, CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessAbsent, CorrelationCompletenessAbsent, "no documented native OTLP surface"))
	case "windsurf":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "trajectory", "trajectory_id", "trajectoryId"),
			reported(CorrelationTargetTurn, ns, "execution", "execution_id", "executionId"),
			reported(CorrelationTargetExecution, ns, "execution", "execution_id", "executionId"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "tool_call_id", "toolCallId"),
			reported(CorrelationTargetSourceSeq, ns, "trajectory_step", "step_index", "stepIndex"),
		)
		return makeSpec(CorrelationProfileWindsurfV1, "windsurf-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, CorrelationCompletenessAbsent, "delegation and per-tool IDs are not consistently reported"))
	case "geminicli":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "session", "sessionId", "conversation_id", "conversationId"),
			reported(CorrelationTargetTurn, ns, "prompt", "prompt_id", "promptId"),
			reported(CorrelationTargetAgent, ns, "agent", "agentId"),
			reported(CorrelationTargetModelRequest, ns, "model_request", "request_id", "requestId"),
			reported(CorrelationTargetModelResponse, ns, "model_response", "response_id", "responseId"),
		)
		native := appendBindings(nativeStandard(ns),
			reported(CorrelationTargetTurn, ns, "prompt", "prompt_id"),
			// Gemini CLI uses the underscore spelling in its native telemetry
			// contract. Keep the standard dotted spelling as separate accepted
			// evidence through nativeStandard for compatible SDK emitters.
			reported(CorrelationTargetTool, ns, "tool_invocation", "gen_ai.tool.call_id"),
		)
		return makeSpec(CorrelationProfileGeminiCLIV1, "geminicli-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook, CorrelationSurfaceNativeOTLP}, bindings, native, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceModelBoundary, CorrelationInferenceUniquePendingTool, CorrelationInferenceTraceLink}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessComplete, "hook tool payloads may omit prompt and tool-call IDs; native tool IDs require trace or pending-operation correlation"))
	case "copilot":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "session", "sessionId"),
			reported(CorrelationTargetChildAgent, ns, "subagent", "subagent_id", "subagentId"),
		)
		native := appendBindings(nativeStandard(ns),
			reported(CorrelationTargetTurn, ns, "turn", "github.copilot.turn_id"),
			// interaction_id identifies one native chat/LLM request, not a user
			// message. Documented hook payloads do not carry this ID.
			reported(CorrelationTargetModelRequest, ns, "interaction", "github.copilot.interaction_id"),
		)
		return makeSpec(CorrelationProfileCopilotV1, "copilot-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook, CorrelationSurfaceNativeOTLP}, bindings, native, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceSubagentIdentity, CorrelationInferenceUniquePendingTool, CorrelationInferenceTraceLink}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessComplete, "documented hooks expose session membership but not native turn, interaction, response, or tool-call IDs"))
	case "openhands":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "conversation", "conversation_id", "conversationId"),
			reported(CorrelationTargetTurn, ns, "message", "message_id", "messageId", "prompt_id", "promptId"),
			reported(CorrelationTargetSourceEvent, ns, "event", "event_id", "eventId"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "tool_call_id", "toolCallId"),
			// OpenHands action_id identifies an action event. It is independent
			// from ActionEvent.tool_call_id and must never populate the canonical
			// tool-invocation field merely because both appear around a tool.
			reported(CorrelationTargetAction, ns, "action", "action_id", "actionId"),
			reported(CorrelationTargetModelResponse, ns, "model_response", "llm_response_id", "llmResponseId"),
		)
		return makeSpec(CorrelationProfileOpenHandsV1, "openhands-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessAbsent, "shell hook lacks the complete event-stream lineage surface; no authenticated event-stream adapter or native exporter is installed"))
	case "antigravity":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "conversation", "conversationId", "conversation_id", "sessionId"),
			// stepIdx is trajectory-step evidence only. It is intentionally
			// absent from CorrelationTargetTurn.
			reported(CorrelationTargetStep, ns, "trajectory_step", "stepIdx", "step_idx"),
			reported(CorrelationTargetExecution, ns, "invocation", "invocationNum", "invocation_num", "executionNum", "execution_num"),
			reported(CorrelationTargetTool, ns, "tool_call", "toolCall.id", "toolCall.callId", "tool_call_id"),
		)
		return makeSpec(CorrelationProfileAntigravityV1, "antigravity-hooks-v2", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferencePromptBoundaryTurn, CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, CorrelationCompletenessPartial, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, "stepIdx is a trajectory step, not a turn", "no documented customer OTLP surface"))
	case "opencode":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "session", "sessionId"),
			reported(CorrelationTargetParentSession, ns, "parent_session", "parentID", "parentId", "parentSessionId"),
			reported(CorrelationTargetTurn, ns, "message", "messageId", "message_id"),
			reported(CorrelationTargetSourceEvent, ns, "part", "part_id", "partId"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "callID", "callId", "toolCallId"),
		)
		return makeSpec(CorrelationProfileOpenCodeV1, "opencode-hooks-v1", []CorrelationSurface{CorrelationSurfaceHook}, bindings, nil, []CorrelationInferenceRule{CorrelationInferenceUniquePendingTool}, complete(CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, "no authenticated server-event adapter or reviewed native exporter is installed"))
	case "omnigent":
		bindings := appendBindings(base,
			reported(CorrelationTargetSession, ns, "conversation", "conversation_id", "conversationId"),
			reported(CorrelationTargetRootSession, ns, "root_conversation", "root_conversation_id", "rootConversationId"),
			reported(CorrelationTargetParentSession, ns, "parent_conversation", "parent_conversation_id", "parentConversationId"),
			reported(CorrelationTargetTurn, ns, "response", "response_id", "responseId"),
			reported(CorrelationTargetAgent, ns, "agent", "agent_id", "agentId"),
			reported(CorrelationTargetTool, ns, "tool_invocation", "call_id", "callId"),
			reported(CorrelationTargetModelRequest, ns, "model_request", "request_id", "requestId"),
			reported(CorrelationTargetSourceEvent, ns, "item", "item_id", "itemId"),
		)
		native := appendBindings(nativeStandard(ns),
			reported(CorrelationTargetTurn, ns, "response", "omnigent.response.id", "response.id"),
			reported(CorrelationTargetSourceEvent, ns, "item", "omnigent.item.id", "item.id"),
		)
		return makeSpec(CorrelationProfileOmniGentV1, "omnigent-custom-policy-v1", []CorrelationSurface{CorrelationSurfaceHook, CorrelationSurfaceNativeOTLP}, bindings, native, []CorrelationInferenceRule{CorrelationInferenceModelBoundary, CorrelationInferenceUniquePendingTool, CorrelationInferenceTraceLink}, complete(CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessComplete, CorrelationCompletenessComplete))
	default:
		return CorrelationSpec{}, false
	}
}

func defaultHookContractID(name string) string {
	resolution := ResolveHookContract(name, "")
	return resolution.Contract.ContractID
}

// DefaultCorrelationSpec is intended for offline fixture/normalizer tests.
// Production HookProfile resolution uses the pinned HookContract ID instead.
func DefaultCorrelationSpec(name string) CorrelationSpec {
	if spec, ok := CorrelationSpecForConnector(name, defaultHookContractID(name)); ok {
		return spec
	}
	return ExplicitCanonicalCorrelationSpec(name)
}

func correlationSpecForOptions(name string, opts SetupOpts) CorrelationSpec {
	contractID := strings.TrimSpace(opts.HookContractID)
	resolution := ResolveHookContract(name, opts.AgentVersion)
	if contractID == "" {
		contractID = resolution.Contract.ContractID
	}
	if resolution.Status == HookCompatibilityUnknown || (resolution.Contract.ContractID != "" && contractID != resolution.Contract.ContractID) {
		spec := ExplicitCanonicalCorrelationSpec(name)
		spec.CompatibilityStatus = resolution.Status
		return spec
	}
	if spec, ok := CorrelationSpecForConnector(name, contractID); ok {
		// A correlation profile may intentionally have a narrower version
		// floor than its hook transport contract when an identity field was
		// added later (Claude prompt_id is one example). Preserve that reviewed
		// floor instead of replacing it with the broader transport range.
		if spec.MinAgentVersion == "" {
			spec.MinAgentVersion = resolution.Contract.MinAgentVersion
		}
		if spec.MaxAgentVersion == "" {
			spec.MaxAgentVersion = resolution.Contract.MaxAgentVersion
		}
		spec.CompatibilityStatus = resolution.Status
		return spec
	}
	return ExplicitCanonicalCorrelationSpec(name)
}

func (c *OpenClawConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (c *ZeptoClawConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (c *ClaudeCodeConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (c *CodexConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (c *hookOnlyConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (c *OmnigentConnector) CorrelationSpec(opts SetupOpts) CorrelationSpec {
	return correlationSpecForOptions(c.Name(), opts)
}

func (s CorrelationSpec) Allows(rule CorrelationInferenceRule) bool {
	for _, candidate := range s.AllowedInferenceRules {
		if candidate == rule {
			return true
		}
	}
	return false
}

func (s CorrelationSpec) AllowsReceiptTarget(target CorrelationTarget) bool {
	for _, candidate := range s.ReceiptTargets {
		if candidate == target {
			return true
		}
	}
	return false
}

func (s CorrelationSpec) AllowsMirrorTarget(target CorrelationTarget) bool {
	for _, candidate := range s.MirrorIdentityTargets {
		if candidate == target {
			return true
		}
	}
	return false
}

func (s CorrelationSpec) LifecycleForEvent(event string) (CorrelationLifecycle, bool) {
	for _, binding := range s.Lifecycle {
		for _, declared := range binding.Events {
			if event == declared {
				return binding.Lifecycle, true
			}
		}
	}
	return "", false
}

func (s CorrelationSpec) Validate() error {
	if strings.TrimSpace(s.Connector) == "" {
		return fmt.Errorf("correlation connector is required")
	}
	if s.ProfileVersion == "" {
		return fmt.Errorf("correlation profile version is required")
	}
	switch s.CompatibilityStatus {
	case HookCompatibilityKnown, HookCompatibilityUnversioned, HookCompatibilityUnknown, HookCompatibilityNotGated:
	default:
		return fmt.Errorf("unknown correlation compatibility status %q", s.CompatibilityStatus)
	}
	if s.MinAgentVersion != "" && s.MaxAgentVersion != "" && !versionInRange(s.MinAgentVersion, s.MinAgentVersion, s.MaxAgentVersion) {
		return fmt.Errorf("correlation agent version range is invalid")
	}
	validOrigin := map[CorrelationOrigin]bool{
		CorrelationOriginReported: true, CorrelationOriginMinted: true,
		CorrelationOriginDerived: true, CorrelationOriginInferred: true,
		CorrelationOriginTraceExact: true,
	}
	validTarget := map[CorrelationTarget]bool{
		CorrelationTargetSemanticEvent: true, CorrelationTargetSession: true, CorrelationTargetTurn: true,
		CorrelationTargetThread:  true,
		CorrelationTargetMessage: true, CorrelationTargetAgent: true, CorrelationTargetAgentName: true,
		CorrelationTargetAgentType: true, CorrelationTargetRootAgent: true, CorrelationTargetParentAgent: true,
		CorrelationTargetChildAgent: true, CorrelationTargetRootSession: true, CorrelationTargetParentSession: true,
		CorrelationTargetChildSession: true, CorrelationTargetTool: true, CorrelationTargetModelRequest: true,
		CorrelationTargetModelResponse: true, CorrelationTargetAction: true, CorrelationTargetSourceEvent: true, CorrelationTargetSourceSeq: true,
		CorrelationTargetSourceTime: true, CorrelationTargetExecution: true, CorrelationTargetStep: true,
	}
	if err := s.validateProvenance(validTarget); err != nil {
		return err
	}
	for _, bindings := range [][]CorrelationFieldBinding{s.HookBindings, s.ProxyBindings, s.StreamBindings, s.NativeOTLPBindings} {
		pathTargets := make(map[string]CorrelationTarget, len(bindings))
		for _, binding := range bindings {
			if !validTarget[binding.Target] {
				return fmt.Errorf("unknown correlation target %q", binding.Target)
			}
			if !validOrigin[binding.Origin] {
				return fmt.Errorf("unknown correlation origin %q", binding.Origin)
			}
			if len(binding.Paths) == 0 || strings.TrimSpace(binding.Namespace) == "" || strings.TrimSpace(binding.IDKind) == "" {
				return fmt.Errorf("binding %q requires paths, namespace and id kind", binding.Target)
			}
			for _, path := range binding.Paths {
				if strings.TrimSpace(path) == "" {
					return fmt.Errorf("binding %q has an empty path", binding.Target)
				}
				if previous, exists := pathTargets[path]; exists {
					if previous == binding.Target {
						return fmt.Errorf("correlation path %q is declared more than once for target %q", path, binding.Target)
					}
					if !s.declaresPathAlias(path, previous, binding.Target) {
						return fmt.Errorf("correlation path %q maps to both %q and %q", path, previous, binding.Target)
					}
				}
				pathTargets[path] = binding.Target
			}
		}
	}
	for _, alias := range s.DeclaredPathAliases {
		if strings.TrimSpace(alias.Path) == "" || len(alias.Targets) < 2 {
			return fmt.Errorf("declared correlation alias requires a path and at least two targets")
		}
		for _, target := range alias.Targets {
			if !validTarget[target] {
				return fmt.Errorf("declared correlation alias has unknown target %q", target)
			}
		}
	}
	for _, targets := range [][]CorrelationTarget{s.ReceiptTargets, s.MirrorIdentityTargets} {
		seen := make(map[CorrelationTarget]bool, len(targets))
		for _, target := range targets {
			if !validTarget[target] || seen[target] {
				return fmt.Errorf("correlation proof target %q is invalid or repeated", target)
			}
			seen[target] = true
		}
	}
	for _, target := range s.MirrorIdentityTargets {
		if target == CorrelationTargetSession || target == CorrelationTargetThread || target == CorrelationTargetTurn ||
			target == CorrelationTargetAgent || target == CorrelationTargetExecution || target == CorrelationTargetStep {
			return fmt.Errorf("membership target %q cannot prove cross-rail mirror identity", target)
		}
	}
	validCompleteness := func(level CorrelationCompletenessLevel) bool {
		switch level {
		case CorrelationCompletenessComplete, CorrelationCompletenessPartial, CorrelationCompletenessAbsent, CorrelationCompletenessUnknown:
			return true
		default:
			return false
		}
	}
	for _, level := range []CorrelationCompletenessLevel{s.Completeness.Session, s.Completeness.Turn, s.Completeness.AgentLifecycle, s.Completeness.Tool, s.Completeness.Model, s.Completeness.NativeOTLP} {
		if !validCompleteness(level) {
			return fmt.Errorf("unknown completeness level %q", level)
		}
	}
	if s.NativeTelemetry.Stability == "" {
		return fmt.Errorf("native telemetry stability is required")
	}
	for _, surface := range s.Surfaces {
		var bindings []CorrelationFieldBinding
		switch surface {
		case CorrelationSurfaceHook:
			bindings = s.HookBindings
		case CorrelationSurfaceProxy:
			bindings = s.ProxyBindings
		case CorrelationSurfaceStream:
			bindings = s.StreamBindings
		case CorrelationSurfaceNativeOTLP:
			bindings = s.NativeOTLPBindings
		default:
			return fmt.Errorf("unknown correlation surface %q", surface)
		}
		if len(bindings) == 0 {
			return fmt.Errorf("correlation surface %q has no reviewed bindings", surface)
		}
	}
	switch s.NativeTelemetry.Stability {
	case NativeTelemetryStable, NativeTelemetryBeta, NativeTelemetryExperimental:
		if len(s.NativeTelemetry.Signals) == 0 || len(s.NativeOTLPBindings) == 0 || s.NativeTelemetry.InputSurface != CorrelationSurfaceNativeOTLP {
			return fmt.Errorf("native-capable profile requires signals and native_otlp input surface")
		}
	case NativeTelemetryNone:
		if len(s.NativeTelemetry.Signals) != 0 || len(s.NativeTelemetry.AuthoritativeFields) != 0 ||
			len(s.MirrorIdentityTargets) != 0 {
			return fmt.Errorf("native telemetry stability none cannot declare signals, authorities, or mirror targets")
		}
	default:
		return fmt.Errorf("unknown native telemetry stability %q", s.NativeTelemetry.Stability)
	}
	authoritative := make(map[CorrelationTarget]bool, len(s.NativeTelemetry.AuthoritativeFields))
	for _, target := range s.NativeTelemetry.AuthoritativeFields {
		if !validTarget[target] || authoritative[target] {
			return fmt.Errorf("authoritative native field %q is invalid or repeated", target)
		}
		authoritative[target] = true
		found := false
		for _, binding := range s.NativeOTLPBindings {
			found = found || binding.Target == target
		}
		if !found {
			return fmt.Errorf("authoritative native field %q has no native binding", target)
		}
	}
	if s.NativeTelemetry.Stability != NativeTelemetryNone {
		for _, target := range s.MirrorIdentityTargets {
			if !s.NativeTelemetry.IsAuthoritative(target) {
				return fmt.Errorf("cross-rail mirror target %q is not authoritative on native telemetry", target)
			}
		}
	}
	return nil
}

func (s CorrelationSpec) declaresPathAlias(path string, targets ...CorrelationTarget) bool {
	for _, alias := range s.DeclaredPathAliases {
		if alias.Path != path {
			continue
		}
		for _, target := range targets {
			found := false
			for _, allowed := range alias.Targets {
				found = found || allowed == target
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

// HookValue resolves one target using only the ordered paths declared by the
// profile. Numeric sequence/step values are preserved as decimal strings.
func (s CorrelationSpec) HookValue(payload map[string]interface{}, target CorrelationTarget) (CorrelationValue, bool) {
	return correlationValueFromBindings(payload, target, s.HookBindings)
}

// HookValues returns every native identifier exposed by the reviewed hook
// contract. HookValue is convenient for selecting the one canonical value for
// a target, but the ledger must retain additional provider IDs (for example a
// message ID and a hook-delivery ID) as separately typed evidence.
func (s CorrelationSpec) HookValues(payload map[string]interface{}) []CorrelationValue {
	return correlationValuesFromBindings(payload, s.HookBindings)
}

// ProxyValues resolves only the normalized fields declared by the authenticated
// proxy adapter. A proxy path never inherits hook or native aliases implicitly.
func (s CorrelationSpec) ProxyValues(payload map[string]interface{}) []CorrelationValue {
	return correlationValuesFromBindings(payload, s.ProxyBindings)
}

// StreamValues resolves only the normalized fields declared by the
// connector's authenticated event-stream adapter.
func (s CorrelationSpec) StreamValues(payload map[string]interface{}) []CorrelationValue {
	return correlationValuesFromBindings(payload, s.StreamBindings)
}

// NativeOTLPValue resolves only attributes declared for the authenticated
// native rail. Hook aliases are intentionally invisible here so a connector
// cannot change an attribute's meaning merely by sending it over OTLP.
func (s CorrelationSpec) NativeOTLPValue(attributes map[string]interface{}, target CorrelationTarget) (CorrelationValue, bool) {
	return correlationValueFromBindings(attributes, target, s.NativeOTLPBindings)
}

// NativeOTLPValues returns every exact native-rail identifier without making
// hook-only aliases visible to the OTLP receiver.
func (s CorrelationSpec) NativeOTLPValues(attributes map[string]interface{}) []CorrelationValue {
	return correlationValuesFromBindings(attributes, s.NativeOTLPBindings)
}

// ValidateCorrelationValues rejects contradictory claims made through two
// aliases that the reviewed profile declares to be the same typed identity.
// Different targets or ID kinds remain independent evidence even when their
// raw values happen to be equal (for example an OpenHands action ID and tool
// invocation ID).
func ValidateCorrelationValues(values []CorrelationValue) error {
	seen := make(map[string]string, len(values))
	for _, value := range values {
		if value.Value == "" {
			continue
		}
		if !utf8.ValidString(value.Value) || len(value.Value) > maxCorrelationProviderIDBytes ||
			strings.TrimSpace(value.Value) != value.Value {
			return fmt.Errorf("invalid correlation value for target %q namespace %q kind %q", value.Target, value.Namespace, value.IDKind)
		}
		for _, char := range value.Value {
			if unicode.IsControl(char) {
				return fmt.Errorf("correlation value for target %q namespace %q kind %q contains a control character", value.Target, value.Namespace, value.IDKind)
			}
		}
		key := string(value.Target) + "\x00" + value.Namespace + "\x00" + value.IDKind
		if previous, ok := seen[key]; ok && previous != value.Value {
			return fmt.Errorf("conflicting correlation aliases for target %q namespace %q kind %q", value.Target, value.Namespace, value.IDKind)
		}
		seen[key] = value.Value
	}
	return nil
}

func correlationValuesFromBindings(payload map[string]interface{}, bindings []CorrelationFieldBinding) []CorrelationValue {
	values := make([]CorrelationValue, 0, len(bindings))
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		for _, path := range binding.Paths {
			value := correlationPathString(payload, path)
			if value == "" {
				continue
			}
			key := string(binding.Target) + "\x00" + binding.Namespace + "\x00" + binding.IDKind + "\x00" + value
			if seen[key] {
				continue
			}
			seen[key] = true
			values = append(values, CorrelationValue{
				Target: binding.Target, Value: value, Path: path, Origin: binding.Origin,
				Namespace: binding.Namespace, IDKind: binding.IDKind,
			})
		}
	}
	return values
}

func correlationValueFromBindings(payload map[string]interface{}, target CorrelationTarget, bindings []CorrelationFieldBinding) (CorrelationValue, bool) {
	var result CorrelationValue
	found := false
	for _, binding := range bindings {
		if binding.Target != target {
			continue
		}
		for _, path := range binding.Paths {
			if value := correlationPathString(payload, path); value != "" {
				// Connector-specific bindings follow generic canonical fallbacks.
				// Prefer the later binding while retaining the first populated path
				// inside that binding as its documented spelling priority.
				result = CorrelationValue{Target: target, Value: value, Path: path, Origin: binding.Origin, Namespace: binding.Namespace, IDKind: binding.IDKind}
				found = true
				break
			}
		}
	}
	return result, found
}

func correlationPathString(payload map[string]interface{}, path string) string {
	if payload == nil || strings.TrimSpace(path) == "" {
		return ""
	}
	// OTLP attribute maps use literal dotted keys (for example
	// "gen_ai.response.id"), while hook payloads sometimes use a declared
	// nested path (for example "extra.session_id"). Prefer an exact map key so
	// the native semantic-convention spelling is never misread as object
	// traversal, then fall back to the one reviewed nested path.
	if direct, ok := payload[path]; ok && direct != nil {
		return correlationScalarString(direct)
	}
	var current interface{} = payload
	for _, part := range strings.Split(path, ".") {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = obj[part]
		if !ok || current == nil {
			return ""
		}
	}
	return correlationScalarString(current)
}

func correlationScalarString(current interface{}) string {
	var value string
	switch v := current.(type) {
	case string:
		value = v
	case fmt.Stringer:
		value = v.String()
	case float64:
		value = strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		value = strconv.FormatFloat(float64(v), 'f', -1, 32)
	case int:
		value = strconv.Itoa(v)
	case int64:
		value = strconv.FormatInt(v, 10)
	case int32:
		value = strconv.FormatInt(int64(v), 10)
	case uint:
		value = strconv.FormatUint(uint64(v), 10)
	case uint64:
		value = strconv.FormatUint(v, 10)
	case uint32:
		value = strconv.FormatUint(uint64(v), 10)
	default:
		return ""
	}
	// Provider identifiers are evidence. Preserve their exact bytes here and
	// let ValidateCorrelationValues reject malformed, padded, control-bearing,
	// or oversized values before they reach the ledger. Sanitizing or
	// truncating an ID would silently change identity and could create a false
	// cross-rail match.
	return value
}
