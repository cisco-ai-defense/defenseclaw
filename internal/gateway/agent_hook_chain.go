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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const toolChainGatewayProjectionRevision = "authenticated-hook-projection-v6"

type toolChainHookCaptureContextKey struct{}

func withToolChainHookCapture(
	ctx context.Context,
	capture *toolChainHookCapture,
) context.Context {
	if ctx == nil || capture == nil {
		return ctx
	}
	return context.WithValue(ctx, toolChainHookCaptureContextKey{}, capture)
}

func toolChainRecorderFromContext(
	ctx context.Context,
) func(actionfacts.Facts, []RuleFinding) {
	if ctx == nil {
		return nil
	}
	capture, _ := ctx.Value(toolChainHookCaptureContextKey{}).(*toolChainHookCapture)
	return toolChainRecorder(capture)
}

// toolChainHookCapture receives the exact ActionFacts and owner decisions from
// trusted dispatch. It prevents the hook boundary from reparsing the action or
// running a second rule scan solely to build chain state.
type toolChainHookCapture struct {
	facts               actionfacts.Facts
	findings            []RuleFinding
	artifactProjections []guardrail.ToolChainProjection
	recorded            bool
}

func (capture *toolChainHookCapture) recordArtifactTrustedAction(
	facts actionfacts.Facts,
	findings []RuleFinding,
	enforcementCapable bool,
) {
	if capture == nil {
		return
	}
	projection := guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}
	projectTrustedActionChainSteps(&projection, facts, findings)
	if !enforcementCapable {
		projection.EnforcementStepMask = 0
	}
	if !toolChainProjectionHasSteps(projection) {
		return
	}
	capture.artifactProjections = append(
		capture.artifactProjections,
		projection,
	)
}

func toolChainRecorder(
	capture *toolChainHookCapture,
) func(actionfacts.Facts, []RuleFinding) {
	if capture == nil {
		return nil
	}
	return capture.recordTrustedAction
}

func (capture *toolChainHookCapture) recordTrustedAction(
	facts actionfacts.Facts,
	findings []RuleFinding,
) {
	if capture == nil {
		return
	}
	capture.facts = facts
	capture.findings = append([]RuleFinding(nil), findings...)
	capture.recorded = true
}

type toolChainHookFinalization struct {
	repository   *audit.ToolChainRepository
	receiptIDs   []string
	evaluationID string
}

type toolChainHookPanicState struct {
	committedBlock agentHookResponse
	finalization   toolChainHookFinalization
	denyCommitted  bool
}

func (finalization toolChainHookFinalization) attach(
	ctx context.Context,
	responseEvaluationID string,
) error {
	if finalization.repository == nil || len(finalization.receiptIDs) == 0 {
		return nil
	}
	evaluationID := firstNonEmpty(finalization.evaluationID, responseEvaluationID)
	if evaluationID == "" {
		// Receipt finalization metadata is optional. The durable receipt still
		// provides exact replay behavior when observability is not configured.
		return nil
	}
	return finalization.repository.AttachFinalization(
		ctx,
		finalization.receiptIDs,
		evaluationID,
		"",
	)
}

func (a *APIServer) applyAgentHookToolChains(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	resp agentHookResponse,
	latency time.Duration,
	panicState *toolChainHookPanicState,
) (agentHookResponse, toolChainHookFinalization) {
	var finalization toolChainHookFinalization
	// Managed enterprise policy is authoritative on hook content. Keep the
	// local semantic/chain lane disabled with the rest of the local scanners
	// so one request cannot produce competing local and managed decisions.
	if a == nil || ManagedEnterpriseActive() || req.toolChain == nil {
		return resp, finalization
	}

	lifecycle := profile.ToolCallLifecycle
	route := lifecycle.RouteForEvent(req.HookEventName)
	structuredAction := route == connector.ToolEventRouteStructuredAction
	stateTransition := route == connector.ToolEventRouteStateTransition
	pairedResult := route == connector.ToolEventRouteResultContent &&
		lifecycle.SupportsExactInvocationJoin()
	lifecycleEligible := profile.ExperimentalToolLifecycleEligible()
	projectionEligible := lifecycleEligible &&
		(structuredAction || stateTransition || pairedResult)
	var projection guardrail.ToolChainProjection
	var typedFindings []RuleFinding
	if projectionEligible {
		projection, typedFindings = projectAgentHookToolChains(req, lifecycle)
	}
	if len(typedFindings) != 0 {
		intent := guardrailRuntimeActionForConnector(
			a.scannerCfg,
			req.ConnectorName,
			HighestSeverity(typedFindings),
			true,
		)
		resp = mergeAgentHookFindings(profile, req, resp, typedFindings, intent)
		if !req.SuppressCorrelationEmit {
			eval := a.emitHookRuleFindings(
				ctx,
				req.ConnectorName,
				req.HookEventName,
				&ToolInspectVerdict{
					Action:           resp.Action,
					Severity:         HighestSeverity(typedFindings),
					Findings:         FindingStrings(typedFindings),
					DetailedFindings: typedFindings,
				},
				hookTargetTypeForEvent(req.HookEventName),
				latency,
			)
			if resp.EvaluationID == "" {
				resp.EvaluationID = eval.EvaluationID
			}
			resp.RuleIDs = mergeBoundedRuleIDs(8, eval.RuleIDs, resp.RuleIDs)
		}
	}
	if stateTransition && resp.Action == guardrailActionBlock {
		// A synchronous transition that DefenseClaw denied is an attempted
		// mutation, not durable evidence that enforcement actually changed.
		return resp, finalization
	}

	if a.store == nil || req.SemanticEventID == "" ||
		req.ConnectorInstanceID == "" {
		return resp, finalization
	}
	repository, err := a.store.ToolChainRepository()
	if err != nil {
		return resp, finalization
	}
	rawFingerprint := sha256.Sum256(rawBody)
	inputFingerprint := hex.EncodeToString(rawFingerprint[:])
	if !lifecycleEligible {
		// Compatibility loss can only reduce authority. Clear the exact
		// authenticated session's pending proposals so an ignored outcome
		// cannot be replayed later after compatibility becomes known again.
		_, _ = repository.DiscardPendingForEventSession(
			ctx,
			audit.ToolChainDiscardPendingForEventSessionInput{
				ConnectorInstanceID:      audit.ConnectorInstanceID(req.ConnectorInstanceID),
				TerminalSemanticEventID:  audit.SemanticEventID(req.SemanticEventID),
				TerminalInputFingerprint: inputFingerprint,
			},
		)
		return resp, finalization
	}
	if lifecycle.IsAuthoritativeTerminalEvent(req.HookEventName) {
		// A reviewed session-end, deletion, or reset boundary clears pending and
		// committed inputs only through the exact authenticated session join. The
		// durable cutoff also prevents stale pre-terminal replays from re-arming
		// state; deny receipts remain replayable. Per-turn Stop/idle events are not
		// terminal. Terminal events never imply tool success or enter semantic
		// chain evaluation themselves.
		_, _ = repository.ResetForTerminalEventSession(
			ctx,
			audit.ToolChainResetForTerminalEventSessionInput{
				ConnectorInstanceID:      audit.ConnectorInstanceID(req.ConnectorInstanceID),
				TerminalSemanticEventID:  audit.SemanticEventID(req.SemanticEventID),
				TerminalInputFingerprint: inputFingerprint,
			},
		)
		return resp, finalization
	}
	if lifecycle.IsAuthoritativePendingDiscardEvent(req.HookEventName) {
		// A reviewed turn/response boundary invalidates unfinished proposals so a
		// late result cannot promote them. Successful predecessors from earlier
		// turns remain available to the same authenticated session.
		_, _ = repository.DiscardPendingForEventSession(
			ctx,
			audit.ToolChainDiscardPendingForEventSessionInput{
				ConnectorInstanceID:      audit.ConnectorInstanceID(req.ConnectorInstanceID),
				TerminalSemanticEventID:  audit.SemanticEventID(req.SemanticEventID),
				TerminalInputFingerprint: inputFingerprint,
			},
		)
		return resp, finalization
	}
	if !projectionEligible {
		return resp, finalization
	}
	rulesetFingerprint, err := activeToolChainRulesetFingerprint(
		req.ConnectorName,
		profile,
	)
	if err != nil {
		return resp, finalization
	}

	predecessorProjection, terminalProjection := splitToolChainProjection(projection)
	observationProjection := projection
	if structuredAction {
		// A pre-tool proposal is not proof that the action ran. Only its
		// terminal-step evidence is evaluated synchronously against prior,
		// outcome-confirmed predecessors. Step-one evidence remains pending
		// until an exact success event promotes it below.
		observationProjection = terminalProjection
	}

	invocationDigest := exactToolChainInvocationDigest(lifecycle, req)
	var result audit.ToolChainObserveResult
	resolvedSuccess := false
	resolvedInvocation := false
	if invocationDigest != "" &&
		lifecycle.ExactInvocationJoinEligible(req.HookEventName) &&
		route == connector.ToolEventRouteResultContent {
		outcome := lifecycle.ClassifyTerminalOutcome(
			req.ConnectorName,
			req.HookEventName,
			req.Payload,
		)
		resolved, resolveErr := repository.ResolvePending(
			ctx,
			audit.ToolChainResolvePendingInput{
				ConnectorInstanceID:      audit.ConnectorInstanceID(req.ConnectorInstanceID),
				ToolInvocationDigest:     invocationDigest,
				Outcome:                  auditToolChainPendingOutcome(outcome),
				RulesetFingerprint:       rulesetFingerprint,
				TerminalSemanticEventID:  audit.SemanticEventID(req.SemanticEventID),
				TerminalInputFingerprint: inputFingerprint,
			},
		)
		if resolveErr != nil {
			return resp, finalization
		}
		resolvedInvocation = resolved.Status == audit.ToolChainPendingResolved
		resolvedSuccess = outcome == connector.ToolLifecycleOutcomeSuccess &&
			resolvedInvocation
		if resolvedSuccess {
			// Terminal-success-only chains are deliberately absent from the
			// synchronous pre-tool observation. Their exact pending projection is
			// matched only after this authenticated success result promotes it.
			result = resolved.Observation
		}
		if outcome != connector.ToolLifecycleOutcomeSuccess {
			// A failed, denied, cancelled, or ambiguous result must not
			// replay command-derived step evidence from its proposal. Retain
			// only independently typed event evidence (for example Claude's
			// invocation-bound PermissionDenied transition).
			typedOnly := req
			typedOnly.toolChain = nil
			observationProjection, _ = projectAgentHookToolChains(typedOnly, lifecycle)
			if !resolvedInvocation {
				// A reported call ID proves only that this result names an
				// invocation. Enforcement state additionally requires the exact
				// prepared proposal in the same authenticated session.
				observationProjection.EnforcementStepMask = 0
			}
		}
	}

	caps := profile.Capabilities
	denyEligible := toolChainProjectionHasBlockIntent(
		a.scannerCfg,
		req.ConnectorName,
		observationProjection,
	) &&
		resp.Mode == "action" &&
		structuredAction &&
		caps.CanBlock &&
		eventIn(req.HookEventName, caps.BlockEvents)
	if denyEligible {
		// The durable repository accepts one deny-eligibility bit for the
		// complete observation. Keep detection evidence for every candidate,
		// but expose enforcement evidence only for chains whose own catalog
		// severity reaches this connector's existing profile threshold. This
		// prevents a CRITICAL candidate on the same sink from promoting an
		// unrelated HIGH match to a block.
		observationProjection = toolChainBlockEligibleProjection(
			a.scannerCfg,
			req.ConnectorName,
			observationProjection,
		)
	}
	if !resolvedSuccess && toolChainProjectionHasSteps(observationProjection) {
		result, err = repository.Observe(ctx, audit.ToolChainObserveInput{
			SemanticEventID:     audit.SemanticEventID(req.SemanticEventID),
			ConnectorInstanceID: audit.ConnectorInstanceID(req.ConnectorInstanceID),
			InputFingerprint:    inputFingerprint,
			RulesetFingerprint:  rulesetFingerprint,
			Projection:          observationProjection,
			DenyEligible:        denyEligible,
		})
		if err != nil {
			return resp, finalization
		}
	}
	if result.DeniedMask != 0 && panicState != nil {
		// Observe commits the deny receipt before returning. Snapshot an
		// enforcement-safe response immediately so a later connector shaper or
		// telemetry panic cannot turn that durable denial back into an allow.
		panicState.committedBlock = committedAgentHookChainPanicBlock(
			profile,
			req,
			resp,
			result,
		)
		if result.Status == audit.ToolChainObserveFresh &&
			len(result.ReceiptIDs) != 0 {
			panicState.finalization.repository = repository
			panicState.finalization.receiptIDs = append(
				[]string(nil),
				result.ReceiptIDs...,
			)
		}
		panicState.denyCommitted = true
	}
	if result.Status == audit.ToolChainObserveFresh &&
		len(result.DetectedChainIDs) != 0 {
		chainFindings := toolChainRuleFindings(result)
		intent := toolChainHookIntent(
			guardrailRuntimeActionForConnector(
				a.scannerCfg,
				req.ConnectorName,
				HighestSeverity(chainFindings),
				true,
			),
			denyEligible,
			result,
		)
		resp = mergeAgentHookFindings(profile, req, resp, chainFindings, intent)
		eval := a.emitHookRuleFindings(
			ctx,
			req.ConnectorName,
			req.HookEventName,
			&ToolInspectVerdict{
				Action:           resp.Action,
				Severity:         HighestSeverity(chainFindings),
				Findings:         FindingStrings(chainFindings),
				DetailedFindings: chainFindings,
			},
			"tool_call_chain",
			latency,
		)
		resp.RuleIDs = mergeBoundedRuleIDs(
			8,
			result.DetectedChainIDs,
			eval.RuleIDs,
			resp.RuleIDs,
		)
		if result.DeniedMask != 0 && eval.EvaluationID != "" {
			resp.EvaluationID = eval.EvaluationID
		} else if resp.EvaluationID == "" {
			resp.EvaluationID = eval.EvaluationID
		}
		finalization.evaluationID = eval.EvaluationID
	} else if result.Status == audit.ToolChainObserveReplay &&
		len(result.DetectedChainIDs) != 0 {
		// Exact transport replays reproduce the durable decision but do not
		// create duplicate finding telemetry.
		chainFindings := toolChainRuleFindings(result)
		intent := toolChainHookIntent(
			guardrailRuntimeActionForConnector(
				a.scannerCfg,
				req.ConnectorName,
				HighestSeverity(chainFindings),
				true,
			),
			denyEligible,
			result,
		)
		resp = mergeAgentHookFindings(profile, req, resp, chainFindings, intent)
		resp.RuleIDs = mergeBoundedRuleIDs(
			8,
			result.DetectedChainIDs,
			resp.RuleIDs,
		)
	}
	if result.DeniedMask != 0 {
		// DeniedMask is possible only when the profile, event, and action mode
		// all proved a synchronous block boundary. A committed receipt remains
		// a deny on exact replay even if the live mode later changes to observe.
		resp = committedAgentHookChainBlock(profile, req, resp)
	}
	if result.Status == audit.ToolChainObserveFresh &&
		len(result.ReceiptIDs) != 0 {
		finalization.repository = repository
		finalization.receiptIDs = append([]string(nil), result.ReceiptIDs...)
	}

	if structuredAction &&
		resp.Action != guardrailActionBlock &&
		invocationDigest != "" &&
		lifecycle.IsPreProposalEvent(req.HookEventName) {
		if _, prepareErr := repository.PreparePending(
			ctx,
			audit.ToolChainPreparePendingInput{
				ConnectorInstanceID:  audit.ConnectorInstanceID(req.ConnectorInstanceID),
				ToolInvocationDigest: invocationDigest,
				PreSemanticEventID:   audit.SemanticEventID(req.SemanticEventID),
				PreInputFingerprint:  inputFingerprint,
				RulesetFingerprint:   rulesetFingerprint,
				Projection:           predecessorProjection,
			},
		); prepareErr != nil {
			// Pending state is an additive experimental lane. A persistence
			// failure must not replace the already-computed direct verdict.
			return resp, finalization
		}
	}
	return resp, finalization
}

func splitToolChainProjection(
	projection guardrail.ToolChainProjection,
) (predecessor guardrail.ToolChainProjection, terminal guardrail.ToolChainProjection) {
	predecessor.ParseStatus = projection.ParseStatus
	terminal.ParseStatus = projection.ParseStatus
	predecessorMask := guardrail.ToolChainArtifactMutationBarrier
	var terminalMask uint64
	for index, definition := range guardrail.ToolChainDefinitions() {
		pendingMask := definition.Step1Bit
		if definition.RequiresTerminalSuccess {
			pendingMask |= definition.Step2Bit | definition.Step3Bit |
				definition.MutationBit
		} else {
			terminalMask |= definition.Step2Bit
		}
		predecessorMask |= pendingMask
		if projection.DetectionStepMask&pendingMask != 0 {
			predecessor.EnforcementJoinDigests[index] =
				projection.EnforcementJoinDigests[index]
		}
		if !definition.RequiresTerminalSuccess &&
			projection.DetectionStepMask&definition.Step2Bit != 0 {
			terminal.EnforcementJoinDigests[index] =
				projection.EnforcementJoinDigests[index]
		}
		if definition.Step3Bit != 0 {
			predecessorMask |= definition.Step2Bit
			if !definition.RequiresTerminalSuccess {
				terminalMask |= definition.Step3Bit
			}
			if definition.OutputJoinFromFirst &&
				projection.DetectionStepMask&definition.Step1Bit != 0 {
				predecessor.EnforcementOutputJoinDigests[index] =
					projection.EnforcementOutputJoinDigests[index]
			}
			if projection.DetectionStepMask&definition.Step2Bit != 0 {
				predecessor.EnforcementJoinDigests[index] =
					projection.EnforcementJoinDigests[index]
				predecessor.EnforcementOutputJoinDigests[index] =
					projection.EnforcementOutputJoinDigests[index]
			}
			if projection.DetectionStepMask&definition.Step3Bit != 0 {
				if definition.RequiresTerminalSuccess {
					predecessor.EnforcementOutputJoinDigests[index] =
						projection.EnforcementOutputJoinDigests[index]
				} else {
					terminal.EnforcementOutputJoinDigests[index] =
						projection.EnforcementOutputJoinDigests[index]
				}
			}
		}
	}
	predecessor.DetectionStepMask = projection.DetectionStepMask & predecessorMask
	predecessor.EnforcementStepMask = projection.EnforcementStepMask & predecessorMask
	terminal.DetectionStepMask = projection.DetectionStepMask & terminalMask
	terminal.EnforcementStepMask = projection.EnforcementStepMask & terminalMask
	return predecessor, terminal
}

func mergeToolChainJoinDigests(
	destination *guardrail.ToolChainProjection,
	source guardrail.ToolChainProjection,
) {
	if destination == nil {
		return
	}
	for index, digest := range source.EnforcementJoinDigests {
		if digest == "" {
			continue
		}
		if destination.EnforcementJoinDigests[index] == "" {
			destination.EnforcementJoinDigests[index] = digest
			continue
		}
		if destination.EnforcementJoinDigests[index] != digest {
			// More than one identity in a single action is useful detection
			// evidence, but it is not a unique enforcement join.
			destination.EnforcementJoinDigests[index] = ""
		}
	}
	for index, digest := range source.EnforcementOutputJoinDigests {
		if digest == "" {
			continue
		}
		if destination.EnforcementOutputJoinDigests[index] == "" {
			destination.EnforcementOutputJoinDigests[index] = digest
			continue
		}
		if destination.EnforcementOutputJoinDigests[index] != digest {
			destination.EnforcementOutputJoinDigests[index] = ""
		}
	}
}

func toolChainProjectionHasSteps(projection guardrail.ToolChainProjection) bool {
	return projection.DetectionStepMask != 0 || projection.EnforcementStepMask != 0
}

func exactToolChainInvocationDigest(
	lifecycle connector.ToolCallLifecycleContract,
	req agentHookRequest,
) string {
	if !lifecycle.ExactInvocationJoinEligible(req.HookEventName) {
		return ""
	}
	value, ok := req.CorrelationValues[connector.CorrelationTargetTool]
	if !ok || value.Origin != connector.CorrelationOriginReported ||
		strings.TrimSpace(value.Value) == "" || value.Value != req.ToolInvocationID {
		return ""
	}
	return correlationValueDigest(
		audit.ConnectorInstanceID(req.ConnectorInstanceID),
		value,
	)
}

func auditToolChainPendingOutcome(
	outcome connector.ToolLifecycleOutcome,
) audit.ToolChainPendingOutcome {
	switch outcome {
	case connector.ToolLifecycleOutcomeSuccess:
		return audit.ToolChainPendingOutcomeSuccess
	case connector.ToolLifecycleOutcomeFailure:
		return audit.ToolChainPendingOutcomeFailure
	case connector.ToolLifecycleOutcomeDenied:
		return audit.ToolChainPendingOutcomeDenied
	case connector.ToolLifecycleOutcomeCancelled:
		return audit.ToolChainPendingOutcomeCancelled
	default:
		return audit.ToolChainPendingOutcomeUnknown
	}
}

func toolChainHookIntent(
	runtimeIntent string,
	denyEligible bool,
	result audit.ToolChainObserveResult,
) string {
	if result.DeniedMask != 0 {
		return guardrailActionBlock
	}
	if result.EnforcementSafeMask == 0 {
		return guardrailActionAlert
	}
	if runtimeIntent == guardrailActionBlock && denyEligible {
		// A synchronous block is valid only after the repository commits the
		// deny receipt. If that invariant is ever broken, retain detection
		// without issuing an uncommitted denial.
		return guardrailActionAlert
	}
	return runtimeIntent
}

func toolChainProjectionHasBlockIntent(
	cfg *config.Config,
	connectorName string,
	projection guardrail.ToolChainProjection,
) bool {
	for _, definition := range guardrail.ToolChainDefinitions() {
		steps := definition.Step1Bit | definition.Step2Bit | definition.Step3Bit
		if projection.EnforcementStepMask&steps != 0 &&
			guardrailRuntimeActionForConnector(
				cfg,
				connectorName,
				definition.Severity,
				true,
			) == guardrailActionBlock {
			return true
		}
	}
	return false
}

func toolChainBlockEligibleProjection(
	cfg *config.Config,
	connectorName string,
	projection guardrail.ToolChainProjection,
) guardrail.ToolChainProjection {
	for index, definition := range guardrail.ToolChainDefinitions() {
		if guardrailRuntimeActionForConnector(
			cfg,
			connectorName,
			definition.Severity,
			true,
		) == guardrailActionBlock {
			continue
		}
		projection.EnforcementStepMask &^=
			definition.Step1Bit | definition.Step2Bit | definition.Step3Bit
		if !definition.RequiresExactJoin {
			projection.EnforcementJoinDigests[index] = ""
			projection.EnforcementOutputJoinDigests[index] = ""
		}
	}
	return projection
}

// DeterministicToolChainSeverity resolves the strongest immutable catalog
// severity for a set of matched chain IDs. The benchmark calls this same
// helper so production and offline scoring cannot drift on chain severity.
func DeterministicToolChainSeverity(ids []string) string {
	findings := make([]RuleFinding, 0, len(ids))
	for _, id := range ids {
		definition, ok := guardrail.ToolChainDefinitionByID(id)
		if !ok {
			continue
		}
		findings = append(findings, RuleFinding{Severity: definition.Severity})
	}
	return HighestSeverity(findings)
}

func (a *APIServer) safeApplyAgentHookToolChains(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	original agentHookResponse,
	latency time.Duration,
) (resp agentHookResponse, finalization toolChainHookFinalization) {
	resp = original
	var panicState toolChainHookPanicState
	defer func() {
		if recovered := recover(); recovered != nil {
			// The chain lane is additive. A local bug or sink panic must never
			// replace an already-computed standalone block with the handler's
			// generic fail-open panic response.
			a.handleHookPanic(
				ctx,
				req.ConnectorName,
				req.HookEventName,
				fmt.Sprintf("tool-call chain panic: %v", recovered),
			)
			if panicState.denyCommitted {
				resp = panicState.committedBlock
				finalization = panicState.finalization
			} else {
				resp = original
				finalization = toolChainHookFinalization{}
			}
		}
	}()
	return a.applyAgentHookToolChains(
		ctx,
		profile,
		req,
		rawBody,
		original,
		latency,
		&panicState,
	)
}

func projectAgentHookToolChains(
	req agentHookRequest,
	lifecycle connector.ToolCallLifecycleContract,
) (guardrail.ToolChainProjection, []RuleFinding) {
	projection := guardrail.ToolChainProjection{
		ParseStatus: actionfacts.StatusNotApplicable,
	}
	capture := req.toolChain
	if capture != nil && capture.recorded {
		projection.ParseStatus = capture.facts.Parse.Status
		projectTrustedActionChainSteps(&projection, capture.facts, capture.findings)
		for _, artifact := range capture.artifactProjections {
			projection.DetectionStepMask |= artifact.DetectionStepMask
			projection.EnforcementStepMask |= artifact.EnforcementStepMask
			mergeToolChainJoinDigests(&projection, artifact)
		}
	}

	permissionDenied, permissionDeniedExact := permissionDeniedChainEvidence(req, lifecycle)
	if permissionDenied {
		addToolChainStep(
			&projection,
			guardrail.ToolChainPermissionDeniedThenBypass,
			1,
			true,
			permissionDeniedExact,
		)
	}
	return projection, nil
}

func projectTrustedActionChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
	findings []RuleFinding,
) {
	found := make(map[string]RuleFinding, len(findings))
	for _, finding := range findings {
		found[finding.RuleID] = finding
	}
	hasAnyFinding := func(ids ...string) bool {
		for _, id := range ids {
			if _, ok := found[id]; ok {
				return true
			}
		}
		return false
	}
	hasEnforceableFinding := func(ids ...string) bool {
		for _, id := range ids {
			if finding, ok := found[id]; ok && finding.contributesToEnforcement() {
				return true
			}
		}
		return false
	}

	secretReadIDs := []string{
		"PATH-ENV-FILE",
		"PATH-SSH-KEY", "PATH-WIN-SSH-KEY",
		"PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS",
		"PATH-KUBE", "PATH-WIN-KUBE-CONFIG",
		"PATH-DOCKER", "PATH-NPMRC", "PATH-PYPIRC",
		"PATH-GIT-CREDS", "PATH-NETRC",
		"PATH-WIN-GIT-CREDS", "PATH-WIN-NETRC",
		"PATH-PROC-ENVIRON", "PATH-ETC-SHADOW",
		"secrets.cloud_credential_read",
		"secrets.browser_session_store_read",
		"secrets.workload_identity_token_read",
	}
	secretRead := hasAnyFinding(secretReadIDs...)
	secretReadDigest, secretReadIdentityExact := exactSingleReadPathDigest(facts)
	secretReadExact := secretRead && secretReadIdentityExact &&
		facts.Authoritative() && facts.EnforcementEligible()
	addToolChainStep(
		projection,
		guardrail.ToolChainSecretReadThenEgress,
		1,
		secretRead,
		secretReadExact,
	)
	if secretReadExact {
		setToolChainEnforcementJoinDigest(
			projection,
			guardrail.ToolChainSecretReadThenEgress,
			secretReadDigest,
		)
	}

	// Chain state is derived from trusted ActionFacts, not from the active
	// profile's atomic alert catalog.  Default and permissive intentionally keep
	// dual-use reads quiet, but those reads must still be available to complete
	// a later bounded proof.
	secretManager := hasAnyFinding("secrets.cloud_secret_manager_read") ||
		cloudSecretManagerPrerequisite(facts)
	secretManagerExact := false
	addToolChainStep(
		projection,
		guardrail.ToolChainSecretManagerReadThenEgress,
		1,
		secretManager,
		secretManagerExact,
	)

	workloadIdentity := hasAnyFinding("secrets.workload_identity_token_read") ||
		pathOwnerPrerequisite(
			pathValueMatcher(matchesWorkloadIdentityToken),
		)(facts)
	workloadIdentityExact := false
	addToolChainStep(
		projection,
		guardrail.ToolChainWorkloadIdentityThenLateralExec,
		1,
		workloadIdentity,
		workloadIdentityExact,
	)

	runtimeBypass := hasAnyFinding("exec.agent_runtime_bypass_flags")
	runtimeBypassExact := facts.Authoritative() &&
		facts.EnforcementEligible() &&
		agentRuntimeBypassPrerequisite(facts) &&
		hasEnforceableFinding("exec.agent_runtime_bypass_flags")
	addToolChainStep(
		projection,
		guardrail.ToolChainPermissionDeniedThenBypass,
		2,
		runtimeBypass,
		runtimeBypassExact,
	)

	privilegeDiscovery, sudoElevation := sudoChainRoles(facts)
	if systemRootPrivilegeDiscovery(facts) {
		privilegeDiscovery = true
	}
	privilegeDiscoveryExact := privilegeDiscovery &&
		facts.Authoritative() &&
		facts.EnforcementEligible()
	addToolChainStep(
		projection,
		guardrail.ToolChainPrivilegeDiscoveryThenElevation,
		1,
		privilegeDiscovery,
		privilegeDiscoveryExact,
	)
	hostNamespace := hasAnyFinding("privilege.host_namespace_entry") &&
		hostNamespaceEntryFallbackProof(facts)
	runtimeSocket := hasAnyFinding("privilege.container_runtime_socket_access") &&
		containerRuntimeSocketPrerequisite(facts)
	privilegeShell := exactPrivilegeShellLaunch(facts)
	privilegeElevation := sudoElevation || privilegeShell || hostNamespace || runtimeSocket
	privilegeElevationExact :=
		(sudoElevation && facts.EnforcementEligible()) ||
			(privilegeShell && facts.EnforcementEligible()) ||
			hostNamespace ||
			(runtimeSocket && facts.EnforcementEligible())
	addToolChainStep(
		projection,
		guardrail.ToolChainPrivilegeDiscoveryThenElevation,
		2,
		privilegeElevation,
		privilegeElevationExact,
	)

	lateral := workloadExecFallbackProof(facts)
	addToolChainStep(
		projection,
		guardrail.ToolChainWorkloadIdentityThenLateralExec,
		2,
		lateral,
		false,
	)

	externalEgress := externalDataBearingUpload(facts)
	uploadDigest, uploadIdentityExact := exactExternalUploadPathDigest(facts)
	egressDetection := externalEgress || hasAnyFinding(
		"CMD-WGET-POST",
		"CMD-CURL-UPLOAD",
		"exfil.secret_read_and_egress_oneliner",
	)
	egressEnforcement := externalEgress && facts.EnforcementEligible()
	for _, chainID := range []string{
		guardrail.ToolChainGuardrailsOffThenEgress,
		guardrail.ToolChainSecretManagerReadThenEgress,
		guardrail.ToolChainSecretReadThenEgress,
	} {
		chainEnforcement := egressEnforcement
		if chainID == guardrail.ToolChainSecretReadThenEgress {
			chainEnforcement = chainEnforcement && uploadIdentityExact
		}
		addToolChainStep(
			projection,
			chainID,
			2,
			egressDetection,
			chainEnforcement,
		)
		if chainEnforcement && chainID == guardrail.ToolChainSecretReadThenEgress {
			setToolChainEnforcementJoinDigest(projection, chainID, uploadDigest)
		}
	}

	projectFirewallTrustExpansionChainSteps(projection, facts)
	projectSQLServerCommandExecutionChainSteps(projection, facts)
	projectPrivilegedKubernetesChainSteps(projection, facts)
	projectWirelessCaptureDeauthChainSteps(projection, facts)
	projectCredentialRemoteExecutionChainSteps(projection, facts)
	projectCloudIAMPrincipalAdminChainSteps(projection, facts)
	projectKubernetesPrivilegedCronJobChainSteps(projection, facts)
	projectSQLCommandUDFChainSteps(projection, facts)
	projectStagedReverseShellPersistenceChainSteps(projection, facts)
	projectRemoteArtifactChainSteps(projection, facts)
	if factsMayMutateArtifact(facts) {
		projection.DetectionStepMask |= guardrail.ToolChainArtifactMutationBarrier
	}
}

func projectStagedReverseShellPersistenceChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainStagedReverseShellPersistence
	operation, digest, ok := actionfacts.ExactStagedPayloadPersistenceOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.StagedPayloadWrite:
		addToolChainStep(projection, chainID, 1, true, true)
	case actionfacts.StagedPersistenceInstall:
		addToolChainStep(projection, chainID, 2, true, true)
	case actionfacts.StagedPayloadMutation:
		definition, found := guardrail.ToolChainDefinitionByID(chainID)
		if !found || definition.MutationBit == 0 {
			return
		}
		projection.DetectionStepMask |= definition.MutationBit
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectSQLCommandUDFChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainSQLCommandUDF
	operation, digest, ok := actionfacts.ExactSQLCommandUDFLineageOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.SQLCommandUDFCreate:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.SQLCommandUDFInvoke:
		addToolChainStep(projection, chainID, 2, true, false)
	case actionfacts.SQLCommandUDFBarrier:
		definition, found := guardrail.ToolChainDefinitionByID(chainID)
		if !found || definition.MutationBit == 0 {
			return
		}
		projection.DetectionStepMask |= definition.MutationBit
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectKubernetesPrivilegedCronJobChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainKubernetesPrivilegedCronJob
	fact, ok := actionfacts.ExactKubernetesCronJobOperation(facts)
	if !ok || fact.CronJobIdentityDigest == "" {
		return
	}
	switch fact.Operation {
	case actionfacts.KubernetesCronJobPrivilegedPatch:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.KubernetesCronJobCreateFrom:
		addToolChainStep(projection, chainID, 2, true, false)
	case actionfacts.KubernetesCronJobPatchBarrier:
		definition, found := guardrail.ToolChainDefinitionByID(chainID)
		if !found || definition.MutationBit == 0 {
			return
		}
		projection.DetectionStepMask |= definition.MutationBit
	default:
		return
	}
	setToolChainEnforcementJoinDigest(
		projection, chainID, fact.CronJobIdentityDigest,
	)
}

func projectCloudIAMPrincipalAdminChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainCloudIAMPrincipalAdmin
	operation, digest, ok := actionfacts.ExactCloudIAMPrincipalOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.CloudIAMUserCreate, actionfacts.CloudIAMRoleCreate:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.CloudIAMUserAdminAttach, actionfacts.CloudIAMRoleAdminAttach:
		addToolChainStep(projection, chainID, 2, true, false)
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectCredentialRemoteExecutionChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainSecretsdumpThenPsExecSameIdentity
	operation, digest, ok := actionfacts.ExactCredentialRemoteExecutionOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.CredentialExtractionSecretsdump:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.CredentialRemoteExecutionPsExec:
		addToolChainStep(projection, chainID, 2, true, false)
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectWirelessCaptureDeauthChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainWirelessCaptureThenDeauthSameBSSID
	operation, digest, ok := actionfacts.ExactWirelessCaptureDeauthOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.WirelessTargetedPacketCapture:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.WirelessDeauthentication:
		addToolChainStep(projection, chainID, 2, true, false)
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectPrivilegedKubernetesChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainPrivilegedKubernetesHostRootExec
	fact, ok := actionfacts.ExactPrivilegedKubernetesOperation(facts)
	if ok {
		switch fact.Operation {
		case actionfacts.KubernetesPrivilegedManifestWrite:
			addToolChainStep(projection, chainID, 1, true, true)
			setToolChainEnforcementJoinDigest(
				projection, chainID, fact.ArtifactIdentityDigest,
			)
			setToolChainEnforcementOutputJoinDigest(
				projection, chainID, fact.PodIdentityDigest,
			)
		case actionfacts.KubernetesManifestApply:
			addToolChainStep(projection, chainID, 2, true, true)
			setToolChainEnforcementJoinDigest(
				projection, chainID, fact.ArtifactIdentityDigest,
			)
		case actionfacts.KubernetesPodHostPathExec:
			addToolChainStep(projection, chainID, 3, true, true)
			setToolChainEnforcementOutputJoinDigest(
				projection, chainID, fact.PodIdentityDigest,
			)
		}
	}
	if digest, exact := actionfacts.ExactSingleArtifactMutationDigest(facts); exact {
		definition, found := guardrail.ToolChainDefinitionByID(chainID)
		if found && definition.MutationBit != 0 {
			projection.DetectionStepMask |= definition.MutationBit
			projection.EnforcementStepMask |= definition.MutationBit
			setToolChainEnforcementJoinDigest(projection, chainID, digest)
		}
	}
}

func projectSQLServerCommandExecutionChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainSQLServerXPCommandShellExecution
	operation, digest, ok := actionfacts.ExactSQLServerCommandExecution(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.SQLServerXPCommandShellEnable:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.SQLServerXPCommandShellInvoke:
		addToolChainStep(projection, chainID, 2, true, false)
	case actionfacts.SQLServerXPCommandShellDisable:
		definition, found := guardrail.ToolChainDefinitionByID(chainID)
		if !found || definition.MutationBit == 0 {
			return
		}
		projection.DetectionStepMask |= definition.MutationBit
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func factsMayMutateArtifact(facts actionfacts.Facts) bool {
	if len(facts.SensitiveEgressArtifactWrites) != 0 ||
		actionfacts.HasStructuredTextReplacement(facts) {
		return true
	}
	for _, candidate := range facts.Paths {
		// Writes to sinks such as /dev/null cannot replace a regular-file
		// artifact. Treating stderr suppression as a mutation barrier breaks
		// otherwise exact lineage across ordinary diagnostic commands.
		if candidate.Flavor == actionfacts.PathFlavorDevice {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend,
			actionfacts.PathAccessDelete:
			return true
		}
	}
	return false
}

func projectFirewallTrustExpansionChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainFirewallExpansionThenDestination
	if address, ok := actionfacts.ExactFirewallTrustExpansionIPv4(facts); ok {
		digest := exactIPv4ToolChainDigest(address)
		addToolChainStep(projection, chainID, 1, digest != "", false)
		setToolChainEnforcementJoinDigest(projection, chainID, digest)
	}
	if address, ok := exactSingleDirectIPv4Destination(facts); ok {
		digest := exactIPv4ToolChainDigest(address)
		addToolChainStep(projection, chainID, 2, digest != "", false)
		setToolChainEnforcementJoinDigest(projection, chainID, digest)
	}
}

func exactSingleDirectIPv4Destination(facts actionfacts.Facts) (string, bool) {
	selected := ""
	for _, network := range facts.Network {
		switch network.Action {
		case actionfacts.NetworkConnect, actionfacts.NetworkDownload,
			actionfacts.NetworkUpload:
		default:
			continue
		}
		if network.TargetKind != actionfacts.NetworkTargetSingleHost ||
			!directExecutingNetworkCommand(facts, network.CommandID) {
			continue
		}
		host := strings.TrimSpace(network.NormalizedHost)
		if host == "" {
			host = strings.TrimSpace(network.Host)
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is4() {
			continue
		}
		canonical := address.String()
		if selected != "" && selected != canonical {
			return "", false
		}
		selected = canonical
	}
	return selected, selected != ""
}

func directExecutingNetworkCommand(facts actionfacts.Facts, commandID int64) bool {
	for _, command := range facts.Commands {
		if command.ID != commandID {
			continue
		}
		return command.Effect == actionfacts.EffectExecute &&
			!command.ControlFlowUncertain && command.ParentCommandID == 0 &&
			command.PipelineID == 0 && command.ArgvComplete
	}
	return false
}

func exactIPv4ToolChainDigest(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return ""
	}
	digest := sha256.Sum256([]byte(
		"defenseclaw/tool-chain/ipv4-identity/v1\x00" + address.String(),
	))
	return hex.EncodeToString(digest[:])
}

func projectRemoteArtifactChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const derivedChainID = guardrail.ToolChainDownloadDecodeExecuteSameArtifact
	const directChainID = guardrail.ToolChainDownloadThenExecuteSameArtifact
	const sensitiveEgressChainID = guardrail.ToolChainSensitiveEgressArtifactThenExec
	if downloaded, ok := actionfacts.ExactRemoteArtifactDownload(facts); ok {
		digest, exact := exactPathDigest(downloaded)
		addToolChainStep(projection, derivedChainID, 1, exact, exact)
		if exact {
			setToolChainEnforcementJoinDigest(projection, derivedChainID, digest)
		}
	}
	if downloaded, ok := actionfacts.ExactRemoteArtifactDownloadIntent(facts); ok {
		digest, exact := exactPathDigest(downloaded)
		addToolChainStep(projection, directChainID, 1, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
		}
	} else if downloaded, ok := actionfacts.BoundedRemoteArtifactDownloadIntent(facts); ok {
		digest, exact := exactPathDigest(downloaded)
		addToolChainStep(projection, directChainID, 1, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
		}
	}
	if written, ok := actionfacts.ExactSensitiveEgressArtifactWrite(facts); ok {
		digest, exact := exactPathDigest(written)
		addToolChainStep(projection, sensitiveEgressChainID, 1, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, sensitiveEgressChainID, digest)
		}
	}
	if input, output, ok := actionfacts.ExactArtifactDecodeTransition(facts); ok {
		inputDigest, inputExact := exactPathDigest(input)
		outputDigest, outputExact := exactPathDigest(output)
		exact := inputExact && outputExact
		addToolChainStep(projection, derivedChainID, 2, exact, exact)
		if exact {
			setToolChainEnforcementJoinDigest(projection, derivedChainID, inputDigest)
			setToolChainEnforcementOutputJoinDigest(projection, derivedChainID, outputDigest)
		}
	}
	if executed, ok := actionfacts.ExactArtifactExecution(facts); ok {
		digest, exact := exactPathDigest(executed)
		addToolChainStep(projection, derivedChainID, 3, exact, exact)
		if exact {
			setToolChainEnforcementOutputJoinDigest(projection, derivedChainID, digest)
		}
	}
	if executed, ok := actionfacts.ExactArtifactExecutionIntent(facts); ok {
		digest, exact := exactPathDigest(executed)
		addToolChainStep(projection, directChainID, 2, exact, false)
		addToolChainStep(projection, sensitiveEgressChainID, 2, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
			setToolChainEnforcementJoinDigest(projection, sensitiveEgressChainID, digest)
		}
	} else if executed, ok := actionfacts.BoundedArtifactExecutionIntent(facts); ok {
		digest, exact := exactPathDigest(executed)
		addToolChainStep(projection, directChainID, 2, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
		}
	}
}

func addToolChainStep(
	projection *guardrail.ToolChainProjection,
	chainID string,
	step int,
	detection bool,
	enforcement bool,
) {
	if projection == nil || !detection {
		return
	}
	bit, ok := guardrail.ToolChainStepMask(chainID, step)
	if !ok {
		return
	}
	projection.DetectionStepMask |= bit
	if enforcement {
		projection.EnforcementStepMask |= bit
	}
}

func setToolChainEnforcementJoinDigest(
	projection *guardrail.ToolChainProjection,
	chainID string,
	digest string,
) {
	if projection == nil || digest == "" {
		return
	}
	index, ok := guardrail.ToolChainIndexByID(chainID)
	if !ok {
		return
	}
	projection.EnforcementJoinDigests[index] = digest
}

func setToolChainEnforcementOutputJoinDigest(
	projection *guardrail.ToolChainProjection,
	chainID string,
	digest string,
) {
	if projection == nil || digest == "" {
		return
	}
	index, ok := guardrail.ToolChainIndexByID(chainID)
	if !ok {
		return
	}
	projection.EnforcementOutputJoinDigests[index] = digest
}

func exactPathDigest(candidate actionfacts.PathFact) (string, bool) {
	identity, ok := exactPathIdentity(candidate)
	if !ok {
		return "", false
	}
	digest := sha256.Sum256([]byte("defenseclaw/tool-chain/path-identity/v1\x00" + identity))
	return hex.EncodeToString(digest[:]), true
}

func exactSingleReadPathDigest(facts actionfacts.Facts) (string, bool) {
	return exactSinglePathDigest(facts, func(candidate actionfacts.PathFact) bool {
		return candidate.Access == actionfacts.PathAccessRead &&
			matchesAnySensitivePathCandidate(semanticPathValue(candidate))
	})
}

func exactExternalUploadPathDigest(facts actionfacts.Facts) (string, bool) {
	externalUploadCommands := make(map[int64]struct{})
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			hasOperation(command, actionfacts.OperationUpload) &&
			hasExternalUpload(facts, command.ID) {
			externalUploadCommands[command.ID] = struct{}{}
		}
	}
	if len(externalUploadCommands) == 0 {
		return "", false
	}
	return exactSinglePathDigest(facts, func(candidate actionfacts.PathFact) bool {
		_, uploadCommand := externalUploadCommands[candidate.CommandID]
		return uploadCommand && candidate.Access == actionfacts.PathAccessRead
	})
}

func exactSinglePathDigest(
	facts actionfacts.Facts,
	selectPath func(actionfacts.PathFact) bool,
) (string, bool) {
	var selected string
	for _, candidate := range facts.Paths {
		if !selectPath(candidate) {
			continue
		}
		identity, ok := exactPathIdentity(candidate)
		if !ok {
			return "", false
		}
		if selected != "" && selected != identity {
			return "", false
		}
		selected = identity
	}
	if selected == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte("defenseclaw/tool-chain/path-identity/v1\x00" + selected))
	return hex.EncodeToString(digest[:]), true
}

func exactPathIdentity(candidate actionfacts.PathFact) (string, bool) {
	resolved := strings.TrimSpace(candidate.Resolved)
	if resolved == "" || strings.ContainsRune(resolved, '\x00') {
		return "", false
	}
	switch candidate.Flavor {
	case actionfacts.PathFlavorPOSIX:
		if !strings.HasPrefix(resolved, "/") {
			return "", false
		}
		return "posix\x00" + resolved, true
	case actionfacts.PathFlavorWindows:
		resolved = strings.ToLower(strings.ReplaceAll(resolved, `\`, "/"))
		if len(resolved) < 3 || resolved[1] != ':' || resolved[2] != '/' {
			return "", false
		}
		return "windows\x00" + resolved, true
	default:
		return "", false
	}
}

func sudoChainRoles(facts actionfacts.Facts) (discovery, elevation bool) {
	for _, command := range facts.Commands {
		matched, determinate := sudoDiscoveryOrElevationDisposition(facts, command)
		if !matched || !determinate || command.Effect != actionfacts.EffectExecute {
			continue
		}
		if hasArgumentFold(command.Argv, "-l") ||
			hasArgumentFold(command.Argv, "-ll") ||
			hasArgumentFold(command.Argv, "--list") {
			discovery = true
		} else {
			elevation = true
		}
	}
	return discovery, elevation
}

func exactPrivilegeShellLaunch(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.PipelineID != 0 ||
			command.Effect != actionfacts.EffectExecute || !command.ArgvComplete {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "doas":
			if len(command.Argv) == 2 &&
				command.Argv[1] == "-s" ||
				exactElevatedShellArgv(command.Argv[1:]) {
				return true
			}
		case "su":
			if len(command.Argv) == 1 ||
				len(command.Argv) == 2 &&
					(command.Argv[1] == "root" || command.Argv[1] == "-" ||
						command.Argv[1] == "-l" || command.Argv[1] == "--login") ||
				len(command.Argv) == 3 &&
					(command.Argv[1] == "-" || command.Argv[1] == "-l" ||
						command.Argv[1] == "--login") &&
					command.Argv[2] == "root" {
				return true
			}
		case "pkexec":
			if exactElevatedShellArgv(command.Argv[1:]) {
				return true
			}
		}
	}
	return false
}

func exactElevatedShellArgv(argv []string) bool {
	if len(argv) == 0 || !shellProgram(argv[0]) {
		return false
	}
	for _, argument := range argv[1:] {
		switch argument {
		case "-i", "-l", "--login", "--noprofile", "--norc":
			continue
		default:
			return false
		}
	}
	return true
}

func systemRootPrivilegeDiscovery(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute || !command.ArgvComplete {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "find":
			if rootFindPrivilegeDiscovery(command.Argv) {
				return true
			}
		case "getcap":
			if rootGetcapDiscovery(command.Argv) {
				return true
			}
		}
	}
	return false
}

func rootFindPrivilegeDiscovery(argv []string) bool {
	if len(argv) < 4 || !systemDiscoveryRoot(argv[1]) {
		return false
	}
	for index := 2; index+1 < len(argv); index++ {
		if argv[index] != "-perm" {
			continue
		}
		mode := strings.ToLower(argv[index+1])
		mode = strings.TrimPrefix(mode, "-")
		mode = strings.TrimPrefix(mode, "/")
		switch mode {
		case "2000", "4000", "6000":
			return true
		}
		if strings.ContainsAny(mode, "+=") &&
			strings.HasSuffix(mode, "s") {
			prefix := strings.TrimSuffix(mode, "s")
			prefix = strings.TrimSuffix(prefix, "+")
			prefix = strings.TrimSuffix(prefix, "=")
			valid := true
			for _, char := range prefix {
				if char != 'u' && char != 'g' && char != 'o' {
					valid = false
					break
				}
			}
			if valid {
				return true
			}
		}
	}
	return false
}

func rootGetcapDiscovery(argv []string) bool {
	return len(argv) == 3 &&
		(argv[1] == "-r" || argv[1] == "--recursive") &&
		systemDiscoveryRoot(argv[2])
}

func systemDiscoveryRoot(value string) bool {
	if value == "/" {
		return true
	}
	switch strings.TrimRight(value, "/") {
	case "/usr", "/bin", "/sbin", "/opt":
		return true
	default:
		return false
	}
}

func externalDataBearingUpload(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationUpload) ||
			!hasExternalUpload(facts, command.ID) {
			continue
		}
		for _, flow := range facts.DataFlows {
			if flow.FromCommandID == command.ID &&
				flow.To == actionfacts.DataNetwork &&
				(flow.From == actionfacts.DataProcess ||
					flow.From == actionfacts.DataStdin ||
					flow.From == actionfacts.DataFile ||
					flow.From == actionfacts.DataStdout) {
				return true
			}
		}
	}
	return false
}

func permissionDeniedChainEvidence(
	req agentHookRequest,
	lifecycle connector.ToolCallLifecycleContract,
) (detected, enforcementSafe bool) {
	event := canonicalEvent(req.HookEventName)
	exactInvocation := exactReportedToolInvocation(lifecycle, req)
	// A connector-authenticated, invocation-bound denial event is the only
	// enforcement-safe predecessor. Generic operating-system access errors are
	// useful intent telemetry but may describe an unrelated file or service.
	if event == "permissiondenied" {
		return true, exactInvocation
	}
	candidates := []map[string]interface{}{req.Payload}
	for _, key := range []string{
		"tool_response", "toolResponse", "tool_result", "toolResult",
		"result", "error",
	} {
		if child := objectAt(req.Payload, key); child != nil {
			candidates = append(candidates, child)
		}
	}
	for _, candidate := range candidates {
		if denied, ok := exactBool(
			candidate,
			"permission_denied",
			"permissionDenied",
			"access_denied",
			"accessDenied",
		); ok && denied {
			exact := event == "posttoolusefailure" && exactInvocation
			return true, exact
		}
		failureType := strings.ToLower(strings.TrimSpace(firstString(
			candidate,
			"failure_type",
			"failureType",
			"outcome",
			"status",
		)))
		if failureType == "permission_denied" || failureType == "permissiondenied" {
			exact := event == "posttoolusefailure" && exactInvocation
			return true, exact
		}
		code := strings.ToUpper(strings.TrimSpace(firstString(
			candidate,
			"error_code",
			"errorCode",
			"code",
			"status_code",
			"statusCode",
		)))
		switch code {
		case "EACCES", "EPERM", "PERMISSION_DENIED", "ACCESS_DENIED":
			return true, false
		}
	}
	return false, false
}

func exactReportedToolInvocation(
	lifecycle connector.ToolCallLifecycleContract,
	req agentHookRequest,
) bool {
	if !lifecycle.ExactInvocationJoinEligible(req.HookEventName) {
		return false
	}
	value, ok := req.CorrelationValues[connector.CorrelationTargetTool]
	return ok && value.Origin == connector.CorrelationOriginReported &&
		strings.TrimSpace(value.Value) != "" && value.Value == req.ToolInvocationID
}

func firstObject(
	payload map[string]interface{},
	keys ...string,
) map[string]interface{} {
	for _, key := range keys {
		if child := objectAt(payload, key); child != nil {
			return child
		}
	}
	return nil
}

func exactBool(
	payload map[string]interface{},
	keys ...string,
) (bool, bool) {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}
		result, exact := value.(bool)
		return result, exact
	}
	return false, false
}

func toolChainRuleFindings(
	result audit.ToolChainObserveResult,
) []RuleFinding {
	enforcementSafe := make(map[string]struct{}, len(result.EnforcementSafeChainIDs))
	for _, id := range result.EnforcementSafeChainIDs {
		enforcementSafe[id] = struct{}{}
	}
	findings := make([]RuleFinding, 0, len(result.DetectedChainIDs))
	for _, id := range result.DetectedChainIDs {
		definition, ok := guardrail.ToolChainDefinitionByID(id)
		if !ok {
			continue
		}
		finding := RuleFinding{
			RuleID: id, Title: definition.Title,
			Severity: definition.Severity, Confidence: 0.98,
			Tags:        []string{"tool-call-chain", "multi-step"},
			enforcement: findingEnforcementDetectionOnly,
		}
		if _, ok := enforcementSafe[id]; ok {
			finding.enforcement = findingEnforcementAllowed
		}
		findings = append(findings, finding)
	}
	return findings
}

func mergeAgentHookFindings(
	profile connector.HookProfile,
	req agentHookRequest,
	resp agentHookResponse,
	findings []RuleFinding,
	rawIntent string,
) agentHookResponse {
	action := resp.Action
	rawAction := resp.RawAction
	wouldBlock := resp.WouldBlock
	if hookActionRank(rawIntent) > hookActionRank(rawAction) {
		mapped, mappedWouldBlock := mapHookActionForProfile(
			rawIntent,
			resp.Mode,
			req.HookEventName,
			profile.Capabilities,
			profile,
			req.Payload,
		)
		rawAction = rawIntent
		if hookActionRank(mapped) > hookActionRank(action) {
			action = mapped
		}
		wouldBlock = wouldBlock || mappedWouldBlock
	}

	severity := resp.Severity
	findingSeverity := HighestSeverity(findings)
	if severityRank[findingSeverity] > severityRank[severity] {
		severity = findingSeverity
	}
	reason := hookSourceReason(resp)
	if len(findings) != 0 {
		ids := make([]string, 0, len(findings))
		for _, finding := range findings {
			ids = append(ids, finding.RuleID)
		}
		reason = appendVerdictReason(
			reason,
			"matched ordered safety rule: "+strings.Join(ids, ", "),
		)
		resp.Findings = appendUniqueStrings(resp.Findings, FindingStrings(findings)...)
	}
	next := agentHookResponseForProfile(
		profile,
		req,
		action,
		rawAction,
		severity,
		reason,
		resp.Findings,
		resp.Mode,
		wouldBlock,
		profile.Capabilities,
	)
	next.EvaluationID = resp.EvaluationID
	next.RuleIDs = append([]string(nil), resp.RuleIDs...)
	next.RedactionEnabled = resp.RedactionEnabled
	return next
}

func committedAgentHookChainBlock(
	profile connector.HookProfile,
	req agentHookRequest,
	resp agentHookResponse,
) agentHookResponse {
	next := agentHookResponseForProfile(
		profile,
		req,
		"block",
		"block",
		resp.Severity,
		hookSourceReason(resp),
		resp.Findings,
		resp.Mode,
		false,
		profile.Capabilities,
	)
	next.EvaluationID = resp.EvaluationID
	next.RuleIDs = append([]string(nil), resp.RuleIDs...)
	next.RedactionEnabled = resp.RedactionEnabled
	return next
}

func committedAgentHookChainPanicBlock(
	profile connector.HookProfile,
	req agentHookRequest,
	resp agentHookResponse,
	result audit.ToolChainObserveResult,
) agentHookResponse {
	chainFindings := toolChainRuleFindings(result)
	if severityRank[HighestSeverity(chainFindings)] > severityRank[resp.Severity] {
		resp.Severity = HighestSeverity(chainFindings)
	}
	if len(chainFindings) != 0 {
		ids := make([]string, 0, len(chainFindings))
		for _, finding := range chainFindings {
			ids = append(ids, finding.RuleID)
		}
		resp.SourceReason = appendVerdictReason(
			hookSourceReason(resp),
			"matched ordered safety rule: "+strings.Join(ids, ", "),
		)
		resp.Findings = appendUniqueStrings(
			resp.Findings,
			FindingStrings(chainFindings)...,
		)
	}
	resp.RuleIDs = mergeBoundedRuleIDs(
		8,
		result.DetectedChainIDs,
		resp.RuleIDs,
	)

	// A profile callback may be the panic source, so the recovery snapshot
	// deliberately uses only the built-in, callback-free wire shapers.
	safeProfile := profile
	safeProfile.Respond = nil
	next := committedAgentHookChainBlock(safeProfile, req, resp)
	switch strings.ToLower(strings.TrimSpace(req.ConnectorName)) {
	case "claudecode":
		next.HookOutput = claudeCodeOutput(
			claudeCodeHookRequest{HookEventName: req.HookEventName},
			next.Action,
			next.RawAction,
			next.Reason,
			next.AdditionalContext,
		)
	case "codex":
		next.HookOutput = codexOutput(
			req.HookEventName,
			next.Action,
			next.RawAction,
			next.Reason,
			next.AdditionalContext,
		)
	}
	return next
}

func hookActionRank(action string) int {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block":
		return 4
	case "confirm":
		return 3
	case "alert":
		return 2
	case "allow":
		return 1
	default:
		return 0
	}
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range append(append([]string(nil), existing...), values...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func mergeBoundedRuleIDs(limit int, groups ...[]string) []string {
	if limit <= 0 {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, group := range groups {
		for _, id := range group {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
			if len(out) == limit {
				return out
			}
		}
	}
	return out
}

var toolChainRelevantRuleIDs = []string{
	"CMD-CURL-UPLOAD",
	"CMD-ENV-DUMP",
	"CMD-SUDO",
	"CMD-WGET-POST",
	"PATH-AWS-CREDS",
	"PATH-DOCKER",
	"PATH-ENV-FILE",
	"PATH-GIT-CREDS",
	"PATH-KUBE",
	"PATH-NETRC",
	"PATH-NPMRC",
	"PATH-PROC-ENVIRON",
	"PATH-PYPIRC",
	"PATH-SSH-KEY",
	"PATH-WIN-AWS-CREDS",
	"PATH-WIN-GIT-CREDS",
	"PATH-WIN-KUBE-CONFIG",
	"PATH-WIN-NETRC",
	"PATH-WIN-SSH-KEY",
	"exec.agent_runtime_bypass_flags",
	"exfil.secret_read_and_egress_oneliner",
	"lateral.workload_exec",
	"privilege.container_runtime_socket_access",
	"privilege.host_namespace_entry",
	"secrets.browser_session_store_read",
	"secrets.cloud_credential_read",
	"secrets.cloud_secret_manager_read",
	"secrets.workload_identity_token_read",
}

func activeToolChainRulesetFingerprint(
	connectorName string,
	profile connector.HookProfile,
) (string, error) {
	generation := snapshotRulePackGeneration(connectorName)
	active := make(map[string]PatternRule, len(toolChainRelevantRuleIDs))
	if generation != nil {
		for _, category := range generation.categories {
			for _, rule := range category.Rules {
				active[rule.ID] = rule
			}
		}
	}
	ids := append([]string(nil), toolChainRelevantRuleIDs...)
	sort.Strings(ids)
	digest := sha256.New()
	writeToolChainDigestPart(digest, toolChainGatewayProjectionRevision)
	writeToolChainDigestPart(digest, profile.ContractID)
	writeToolChainDigestPart(digest, profile.HookScriptVersion)
	writeToolChainDigestPart(digest, profile.NormalizedAgentVersion)
	writeToolChainDigestPart(digest, profile.CompatibilityStatus)
	lifecycleJSON, err := json.Marshal(profile.ToolCallLifecycle)
	if err != nil {
		return "", err
	}
	writeToolChainDigestPart(digest, string(lifecycleJSON))
	for _, id := range ids {
		writeToolChainDigestPart(digest, id)
		rule, ok := active[id]
		if !ok {
			writeToolChainDigestPart(digest, "missing")
			continue
		}
		pattern := ""
		if rule.Pattern != nil {
			pattern = rule.Pattern.String()
		}
		writeToolChainDigestPart(digest, pattern)
		writeToolChainDigestPart(digest, rule.Expression)
		writeToolChainDigestPart(digest, strconv.FormatBool(rule.ToolCallOnly))
		writeToolChainDigestPart(digest, rule.Title)
		writeToolChainDigestPart(digest, rule.Severity)
		writeToolChainDigestPart(digest, strconv.FormatFloat(rule.Confidence, 'g', -1, 64))
		for _, tag := range rule.Tags {
			writeToolChainDigestPart(digest, tag)
		}
	}
	return guardrail.ToolChainRulesetFingerprint(
		hex.EncodeToString(digest.Sum(nil)),
	)
}

type toolChainHashWriter interface {
	Write([]byte) (int, error)
}

func writeToolChainDigestPart(writer toolChainHashWriter, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}
