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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

const toolChainGatewayProjectionRevision = "authenticated-hook-projection-v12-sqlite-database-table-lineage"

type toolValueLineageProcessKey struct {
	material  [32]byte
	available bool
}

var activeToolValueLineageProcessKey = newToolValueLineageProcessKey()

func newToolValueLineageProcessKey() toolValueLineageProcessKey {
	var result toolValueLineageProcessKey
	if _, err := rand.Read(result.material[:]); err != nil {
		return result
	}
	result.available = true
	return result
}

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
	return toolChainRecorder(ctx, profileRequestConnector(ctx), capture)
}

// toolChainHookCapture receives the exact ActionFacts and owner decisions from
// trusted dispatch. It prevents the hook boundary from reparsing the action or
// running a second rule scan solely to build chain state.
type toolChainHookCapture struct {
	facts               actionfacts.Facts
	findings            []RuleFinding
	artifactProjections []guardrail.ToolChainProjection
	successfulSQLResult *toolValueLineageSQLSuccessfulProjection
	recorded            bool
	// reportedCWD is the directory the agent reported for the call, as sent
	// and before the gateway checked it. It is agent text: it is only joined
	// to relative operands of a credentials-file read or an external upload
	// (placeSecretReadPaths), and nothing is read there.
	reportedCWD string
	// chainEvidence is what the repositories reported of the chains this
	// call completed, for its audit row (GAP-0445); telemetry only.
	chainEvidence []audit.ToolChainMatchEvidence
}

// noteChainEvidence keeps the evidence of the chains a fresh observation
// detected, from the session window and what the root window added.
func (capture *toolChainHookCapture) noteChainEvidence(results ...audit.ToolChainObserveResult) {
	if capture == nil {
		return
	}
	for _, result := range results {
		if result.Status != audit.ToolChainObserveFresh {
			continue
		}
		for _, ev := range result.Evidence {
			if slices.Contains(result.DetectedChainIDs, ev.ChainID) {
				capture.chainEvidence = append(capture.chainEvidence, ev)
			}
		}
	}
}

// toolChainEvidenceAuditExtra is the chain evidence of the request's audit
// row: one key per field, the values of several chains in the order of
// chain_match_ids (GAP-0445).
func toolChainEvidenceAuditExtra(ctx context.Context) map[string]string {
	if ctx == nil {
		return nil
	}
	capture, _ := ctx.Value(toolChainHookCaptureContextKey{}).(*toolChainHookCapture)
	if capture == nil || len(capture.chainEvidence) == 0 {
		return nil
	}
	cols := map[string][]string{}
	add := func(k, v string) { cols[k] = append(cols[k], v) }
	for _, ev := range capture.chainEvidence {
		add("chain_match_ids", ev.ChainID)
		add("chain_match_scope", ev.Scope)
		add("chain_match_partition", firstNonEmpty(ev.Partition, "-"))
		add("chain_match_sequence", strconv.FormatUint(ev.Sequence, 10))
		add("chain_match_steps", strconv.Itoa(ev.Steps))
		add("chain_match_artifact", firstNonEmpty(ev.Artifact, "-"))
		add("chain_match_span_ms", strconv.FormatInt(ev.SpanMillis, 10))
		add("chain_match_horizon_s", strconv.FormatInt(ev.HorizonSeconds, 10))
	}
	extra := make(map[string]string, len(cols))
	for k, v := range cols {
		extra[k] = strings.Join(v, ",")
	}
	return extra
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
	ctx context.Context,
	connectorName string,
	capture *toolChainHookCapture,
) func(actionfacts.Facts, []RuleFinding) {
	if capture == nil {
		return nil
	}
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || resolved.set == nil {
		return capture.recordTrustedAction
	}
	meet := resolved.evaluationMeet()
	if meet == nil {
		return capture.recordTrustedAction
	}
	return func(facts actionfacts.Facts, findings []RuleFinding) {
		// Keep the full member list for the caller's verdict and audit. Only
		// findings from members that enforce this hook may seed chain steps.
		chainFindings := make([]RuleFinding, 0, len(findings))
		for _, finding := range findings {
			if finding.profile == "" || !slices.Contains(meet.members, finding.profile) ||
				configBlocksOn(resolved.set.profileConfig(finding.profile), connectorName, profilePathHook) {
				chainFindings = append(chainFindings, finding)
			}
		}
		capture.recordTrustedAction(facts, chainFindings)
	}
}

func (capture *toolChainHookCapture) recordTrustedAction(
	facts actionfacts.Facts,
	findings []RuleFinding,
) {
	if capture == nil {
		return
	}
	capture.facts = placeArtifactIntentPaths(placeSecretReadPaths(facts, capture.reportedCWD), capture.reportedCWD)
	capture.findings = append([]RuleFinding(nil), findings...)
	capture.recorded = true
}

// toolChainPlacedFacts is a call's facts as the tool-chain state records
// them. A managed POSIX gateway runs as a service account behind
// ProtectHome (and PrivateTmp on Linux): it cannot resolve a working
// directory in the caller's home, or in /tmp on Linux, so a call there had
// facts without one, and a relative download and the later run of the same
// file had no path to join on. The download-then-execute chain fired for
// absolute paths and in directories the service can read, never in a
// project in the user's home, where agents work (rel-1-0-6:GAP-0115 macOS,
// GAP-0118 Linux). The chain joins paths lexically, so such a call is placed
// in the directory the managed hook client ran it in as the user
// (hookpaths.CWDKey; absolute, no ".."), as a per-user gateway places it. The
// gateway still reads nothing there. A call whose facts hold no unplaced
// relative path, a call the gateway placed itself, and a per-user or sandbox
// call are recorded as they are.
func toolChainPlacedFacts(facts actionfacts.Facts, request trustedActionRequest) actionfacts.Facts {
	if !request.ProtectedHomeHook || request.SkipLocalFilesystemResolution ||
		filepath.IsAbs(request.Input.CWD) || !hasUnplacedRelativePath(facts) {
		return facts
	}
	client := request.evidenceCWD
	if !filepath.IsAbs(client) {
		client = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	if !filepath.IsAbs(client) || hasParentElement(client) || strings.ContainsRune(client, 0) {
		return facts
	}
	placed := request.Input
	placed.CWD = filepath.Clean(client)
	return actionfacts.Analyze(placed)
}

// placeArtifactIntentPaths places, in the directory the agent reported, the
// relative artifact of a remote download (curl -o tool.sh, wget -O tool.sh)
// and the relative script a call runs (bash tool.sh, ./tool.sh), when the
// gateway could not resolve the call's directory (it does not exist on this
// host: an Agent Substrate actor, whose folder is in the actor). Without it
// the relative spelling named no artifact, so chain.download_then_execute_
// same_artifact never joined curl -o tool.sh to bash tool.sh or to bash
// /work/p1/tool.sh in an actor, while the absolute spelling did
// (substrate-1:GAP-0493). The rule is placeSecretReadPaths': an absolute,
// clean reported directory; a literal POSIX operand with no expansion or
// glob character; and every other command of the call one that cannot
// change the directory (callProvenToKeepDirectory's table), so the operand
// names the file the command opened. The download chain is detection-only,
// so a placement can add an alert, never a block. The facts are copied.
func placeArtifactIntentPaths(facts actionfacts.Facts, reported string) actionfacts.Facts {
	if facts.CWD != "" || toolChainDriveMounts || !strings.HasPrefix(reported, "/") ||
		hasParentElement(reported) || strings.ContainsRune(reported, 0) ||
		(facts.Parse.Status != actionfacts.StatusComplete && facts.Parse.Status != actionfacts.StatusPartial) ||
		facts.Parse.Dialect != actionfacts.DialectPOSIX {
		// Partial is what a call with an unresolved relative operand parses
		// as when there is no directory: that operand is what is placed.
		return facts
	}
	reported = path.Clean(reported)
	var placed []actionfacts.PathFact
	for i, candidate := range facts.Paths {
		value := candidate.Value
		// A bare relative operand (tool.sh) has no flavor of its own: the
		// facts give a POSIX one only to ./x, ../x, ~/x and /x. In a POSIX
		// call it is a POSIX path, placed as one.
		if candidate.Absolute || candidate.Resolved != "" ||
			(candidate.Flavor != actionfacts.PathFlavorPOSIX && candidate.Flavor != actionfacts.PathFlavorUnknown) ||
			strings.ContainsAny(value, ":") ||
			(candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessExecute) ||
			value == "" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || hasParentElement(value) ||
			strings.ContainsAny(value, "\\$*?[]{}`\x00") {
			continue
		}
		owner, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || owner.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		if candidate.Access == actionfacts.PathAccessWrite && owner.Program != "curl" && owner.Program != "wget" {
			continue
		}
		if !othersKeepDirectory(facts, candidate.CommandID) {
			continue
		}
		if placed == nil {
			placed = slices.Clone(facts.Paths)
		}
		placed[i].Resolved, placed[i].Flavor = path.Join(reported, value), actionfacts.PathFlavorPOSIX
	}
	if placed != nil {
		facts.Paths = placed
	}
	return facts
}

// othersKeepDirectory reports that every command of the call but owner is
// one that cannot change the directory (directoryKeepingPrograms, a
// standard file reader, or chmod, which a download is usually chained to):
// the owner's operand is then read in the directory the call started in,
// whatever the order of the commands. chmod is added here only, not to
// directoryKeepingPrograms, so the secret-read chain's proofs are unchanged.
func othersKeepDirectory(facts actionfacts.Facts, owner int64) bool {
	for _, command := range facts.Commands {
		if command.ID == owner || command.Program == "chmod" {
			continue
		}
		if _, ok := directoryKeepingPrograms[command.Program]; !ok && !actionfacts.StandardFileReaderProgram(command.Program) {
			return false
		}
	}
	return true
}

// placeSecretReadPaths places a relative operand of a credentials-file read or
// an external upload that the gateway could not resolve (the call's directory
// does not exist on this host, so the call has none) in the directory the
// agent reported, lexically: the read of ".env" and the upload of
// "/work/p/.env" then name one file (substrate-1:GAP-0388). Only absolute,
// clean reported directories are used, and only operands without expansion or
// glob characters; the facts are copied, never changed in place.
func placeSecretReadPaths(facts actionfacts.Facts, reported string) actionfacts.Facts {
	if facts.CWD != "" || toolChainDriveMounts || !strings.HasPrefix(reported, "/") ||
		hasParentElement(reported) || strings.ContainsRune(reported, 0) ||
		!hasUnplacedRelativePath(facts) || !callProvenToKeepDirectory(facts) {
		return facts
	}
	reported = path.Clean(reported)
	uploads := make(map[int64]struct{})
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			hasOperation(command, actionfacts.OperationUpload) &&
			hasExternalUpload(facts, command.ID) {
			uploads[command.ID] = struct{}{}
		}
	}
	var placed []actionfacts.PathFact
	for i, candidate := range facts.Paths {
		value := candidate.Value
		if candidate.Absolute || candidate.Resolved != "" || candidate.Access != actionfacts.PathAccessRead ||
			candidate.Flavor == actionfacts.PathFlavorWindows || value == "" ||
			strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") ||
			strings.ContainsAny(value, "\\$*?[]{}`\x00") {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || command.Dialect != actionfacts.DialectPOSIX && command.Dialect != actionfacts.DialectArgv {
			continue
		}
		_, upload := uploads[candidate.CommandID]
		if _, read := credentialFileContentReadCommand(facts, candidate); !read && !upload {
			continue
		}
		if placed == nil {
			placed = slices.Clone(facts.Paths)
		}
		placed[i].Resolved = path.Join(reported, value)
	}
	if placed != nil {
		facts.Paths = placed
	}
	// The chain's private record is placed by the same lexical rule
	// (actionfacts.Facts.PlaceCredentialPathReads), so a relative read in it
	// has the identity an ordinary read of the same file has.
	return facts.PlaceCredentialPathReads(reported)
}

func hasUnplacedRelativePath(facts actionfacts.Facts) bool {
	for _, candidate := range facts.CredentialPathReads() {
		if candidate.Value != "" && !candidate.Absolute && candidate.Resolved == "" {
			return true
		}
	}
	for _, candidate := range facts.Paths {
		if !candidate.Absolute && candidate.Resolved == "" {
			return true
		}
	}
	return false
}

type toolChainHookFinalization struct {
	repository   toolChainStore
	receiptIDs   []string
	evaluationID string
	// rootRepository and rootReceiptIDs are the root scope's receipts
	// (issue #1391, or a Substrate actor's window), kept in the root tables.
	rootRepository toolChainStore
	rootReceiptIDs []string
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
	session := finalization.repository != nil && len(finalization.receiptIDs) != 0
	root := finalization.rootRepository != nil && len(finalization.rootReceiptIDs) != 0
	if !session && !root {
		return nil
	}
	evaluationID := firstNonEmpty(finalization.evaluationID, responseEvaluationID)
	if evaluationID == "" {
		// Receipt finalization metadata is optional. The durable receipt still
		// provides exact replay behavior when observability is not configured.
		return nil
	}
	if session {
		if err := finalization.repository.AttachFinalization(
			ctx,
			finalization.receiptIDs,
			evaluationID,
			"",
		); err != nil {
			return err
		}
	}
	if root {
		return finalization.rootRepository.AttachFinalization(
			ctx,
			finalization.rootReceiptIDs,
			evaluationID,
			"",
		)
	}
	return nil
}

func (a *APIServer) applyAgentHookToolChains(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	resp agentHookResponse,
	latency time.Duration,
	panicState *toolChainHookPanicState,
) (hookResp agentHookResponse, hookFinalization toolChainHookFinalization) {
	var finalization toolChainHookFinalization
	// Managed enterprise policy is authoritative on hook content. Keep the
	// local semantic/chain lane disabled with the rest of the local scanners
	// so one request cannot produce competing local and managed decisions.
	// The switch is the host daemon's: a verified Substrate actor's steps
	// always feed its actor window on the leader, which the callout's egress
	// check reads, in every tier (GAP-0211).
	if a == nil || (ManagedEnterpriseActive() && !isSubstrateActorRequest(ctx)) || req.toolChain == nil {
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
	// A verified Substrate actor's tool step must reach its actor window on
	// the leader: the callout's egress check reads it (GAP-0201). A step
	// that can't is reported, never skipped silently: rootMissed says why.
	_, substrateActor := substrateActorFrom(ctx)
	// A tool call on an event the connector's lifecycle routes nowhere (a
	// contract with no lifecycle, or an event it does not name) is a step
	// too: it is reported, never skipped silently (GAP-0339).
	unroutedToolCall := route == connector.ToolEventRouteUnknown &&
		strings.TrimSpace(req.ToolName) != "" && !req.ToolNameIsLabel
	substrateStep := substrateActor &&
		(structuredAction || route == connector.ToolEventRouteResultContent || unroutedToolCall)
	rootMissed := ""
	switch {
	case substrateStep && substrateRegistrationNamesNoConnector(ctx):
		rootMissed = "no attested connector is recorded for the actor (an actor made outside DefenseClaw whose template's attestation names none or could not be checked yet), so no reviewed hook contract applies"
	case substrateStep && unroutedToolCall:
		rootMissed = "the actor's hook contract routes no tool-call lifecycle event " + strconv.Quote(req.HookEventName)
	case substrateStep && !lifecycleEligible:
		rootMissed = "the hook contract is not one this gateway reviewed for the actor's agent version (" +
			profile.CompatibilityReason + ")"
	}
	defer func() {
		if substrateStep && rootMissed != "" {
			hookResp = a.substrateChainUnrecorded(ctx, profile, req, hookResp, latency, rootMissed)
		}
	}()
	var projection guardrail.ToolChainProjection
	var typedFindings []RuleFinding
	if projectionEligible {
		projection, typedFindings = projectAgentHookToolChains(req, lifecycle)
		if structuredAction {
			projectSQLValuePersistenceSink(ctx, req, &projection)
		}
		decision := a.decisionConfig(ctx)
		projection = toolChainProjectionForPolicyPosture(
			decision,
			req.ConnectorName,
			projection,
		)
		if a.expectedRemoteDownload(ctx, decision, req) {
			// A download from an internal domain, or one the user asked for
			// and asked to run, does not start the download-then-execute
			// chain.
			clearToolChainStep(&projection, guardrail.ToolChainDownloadThenExecuteSameArtifact, 1)
		}
	}
	if len(typedFindings) != 0 {
		intent := guardrailActionForConnector(
			a.decisionConfig(ctx),
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
		if lifecycleEligible {
			rootMissed = "the hook event has no correlation on this gateway replica"
		}
		return resp, finalization
	}
	// Root scope (issue #1391): nil unless guardrail.chains.root_scope is on
	// and a trusted connector's root_session_id was honoured. Session ends and
	// turn boundaries reset only the session scope: the root scope follows
	// the work across them, bounded by the same event and time windows. A
	// verified Substrate actor's session and actor windows are on the leader
	// (toolChainStores).
	repository, rootRepository, ok := a.toolChainStores(ctx, req)
	if !ok {
		if lifecycleEligible {
			rootMissed = "this gateway replica has no binding to the leader's chain state"
		}
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
		if route == connector.ToolEventRouteResultContent {
			if why := a.resolveCommandJoinedSecretRead(ctx, req, profile, repository, rootRepository, inputFingerprint, projection); why != "" {
				rootMissed = why
			}
		}
		return resp, finalization
	}
	rulesetFingerprint, err := toolChainRulesetFingerprint(
		ctx,
		req.ConnectorName,
		profile,
	)
	if err != nil {
		// No fingerprint, no observation: an actor's step is reported, not
		// dropped (GAP-0201 residual).
		rootMissed = "the active tool chain ruleset could not be fingerprinted: " + err.Error()
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

	invocationDigest := exactToolChainInvocationDigest(ctx, lifecycle, req)
	if structuredAction && invocationDigest == "" &&
		lifecycle.IsPreProposalEvent(req.HookEventName) &&
		resp.Action != guardrailActionBlock {
		// No result can be tied to this call (the connector names no tool
		// invocation, or this call carries none): nothing will ever say
		// what it printed, so its credentials read starts the chain here,
		// at the proposal (the secret-read chain start, GAP-0338).
		started := withSecretReadStart(observationProjection, predecessorProjection)
		switch {
		case started.DetectionStepMask == observationProjection.DetectionStepMask:
		case a.prepareCommandJoinedSecretRead(ctx, req, repository, rootRepository, rulesetFingerprint, inputFingerprint, predecessorProjection):
			// Its result carries the call's command and output: that result
			// decides, as for a paired call (GAP-0340). The pending read counts
			// at the callout from now on.
			started = observationProjection
		default:
			a.noteUnclearedRead(ctx, req.ConnectorName)
		}
		observationProjection = started
	}
	var result, rootResult audit.ToolChainObserveResult
	resolvedSuccess := false
	resolvedInvocation := false
	rootResolvedSuccess := false
	if invocationDigest != "" &&
		lifecycle.ExactInvocationJoinEligible(req.HookEventName) &&
		route == connector.ToolEventRouteResultContent {
		outcome := lifecycle.ClassifyTerminalOutcome(
			req.ConnectorName,
			req.HookEventName,
			req.Payload,
		)
		readPathDigest, readValueDigests :=
			toolValueLineageSuccessfulReadResult(ctx, req, outcome)
		var (
			sqlSource                  audit.ToolChainPendingSQLValueSource
			sqlProjection              toolValueLineageSQLSuccessfulProjection
			sqlProjected               bool
			returnedCredentialMaterial actionfacts.ReturnedCredentialMaterial
			adcsCertificatePFXDigest   string
			s4uTicketResult            actionfacts.KerberosS4UTicketResultFact
		)
		if outcome == connector.ToolLifecycleOutcomeSuccess {
			sqlSource, sqlProjection, sqlProjected =
				projectSuccessfulSQLResultCandidate(ctx, req)
			if resultBytes, exact := exactReturnedCredentialResultBytes(req, outcome); exact {
				returnedCredentialMaterial =
					actionfacts.ClassifyReturnedCredentialMaterial(resultBytes)
				adcsCertificatePFXDigest =
					actionfacts.ExactADCSCertificatePFXResult(resultBytes)
				s4uTicketResult, _ =
					actionfacts.ExactKerberosS4UTicketResultProjection(resultBytes)
			}
		}
		resolveInput := audit.ToolChainResolvePendingInput{
			ConnectorInstanceID:                 audit.ConnectorInstanceID(req.ConnectorInstanceID),
			ToolInvocationDigest:                invocationDigest,
			Outcome:                             auditToolChainPendingOutcome(outcome),
			RulesetFingerprint:                  rulesetFingerprint,
			TerminalSemanticEventID:             audit.SemanticEventID(req.SemanticEventID),
			TerminalInputFingerprint:            inputFingerprint,
			SuccessfulReadPathDigest:            readPathDigest,
			SuccessfulReadValueDigests:          readValueDigests,
			SuccessfulSQLValueSource:            sqlSource,
			SuccessfulSQLResourceIdentityDigest: sqlProjection.resourceIdentityDigest,
			SuccessfulSQLValueDigests: toolValueLineageGuardrailDigests(
				sqlProjection.valueDigests,
			),
			SuccessfulADCSCertificatePFXDigest:         adcsCertificatePFXDigest,
			SuccessfulS4UTargetPrincipalIdentityDigest: s4uTicketResult.TargetPrincipalIdentityDigest,
			SuccessfulS4UTicketCacheDigest:             s4uTicketResult.TicketArtifactIdentityDigest,
		}
		ran := outcome != connector.ToolLifecycleOutcomeDenied && outcome != connector.ToolLifecycleOutcomeCancelled
		if outcome == connector.ToolLifecycleOutcomeFailure || outcome == connector.ToolLifecycleOutcomeUnknown {
			// The call ran (or may have) and did not succeed: the secret-read
			// chain start decides by what it printed (GAP-0337).
			resolveInput.UnsuccessfulMayHaveRead = !toolResultProvesNothingRead(req)
		}
		if substrateActor && ran {
			// A further result of a call the leader already resolved (Claude
			// Code and Cursor post a failure result and then a PostToolUse for
			// one failed call; the kit retries a post) is a replay there, and
			// one whose content may show a read still starts the secret-read
			// chain from the call's proposal (GAP-0348, GAP-0345).
			resolveInput.ResultMayHaveRead = resolveInput.UnsuccessfulMayHaveRead ||
				outcome == connector.ToolLifecycleOutcomeSuccess && !toolResultProvesNothingRead(req)
			// After an earlier result proved the read failed, only a result
			// that shows a read chains: Claude Code's PostToolUse after a
			// PostToolUseFailure carries no output (GAP-0352).
			resolveInput.ResultShowsRead = resolveInput.ResultMayHaveRead && resultShowsRead(req)
		}
		resolved, resolveErr := repository.ResolvePending(ctx, resolveInput)
		var rootStatus audit.ToolChainPendingStatus
		rootFailed := false
		if rootRepository != nil {
			// The root scope promotes its own copy of the proposal; a failure
			// there leaves the session verdict as it is.
			rootResolved, rootErr := rootRepository.ResolvePending(ctx, resolveInput)
			if rootErr == nil &&
				outcome == connector.ToolLifecycleOutcomeSuccess &&
				rootResolved.Status == audit.ToolChainPendingResolved {
				rootResult, rootResolvedSuccess = rootResolved.Observation, true
			}
			rootStatus, rootFailed = rootResolved.Status, rootErr != nil
			if rootErr != nil {
				rootMissed = "the leader did not take the step: " + rootErr.Error()
			}
		}
		if resolveErr != nil {
			return resp, finalization
		}
		if substrateActor && ran && resultCallUnjoined(resolved.Status, rootRepository != nil, rootStatus, rootFailed) &&
			resultMayBeAnUnjoinedRead(req, projection) {
			// The call ran (or may have) but the actor window does not know
			// it: its PreToolUse reached no leader (a replica cut off from
			// it, or a leader that lost or evicted it since), so the read may
			// be in no window at all. The step is reported unrecorded, and
			// the leader keeps that for the callout (review rch3 R1).
			rootMissed = "a tool result whose call is not in the actor's chain window (its call did not reach the leader)"
		}
		resolvedInvocation = resolved.Status == audit.ToolChainPendingResolved
		resolvedSuccess = outcome == connector.ToolLifecycleOutcomeSuccess &&
			resolvedInvocation
		if resolvedSuccess {
			if sqlProjected && resolved.SQLValueSource == sqlSource {
				req.toolChain.successfulSQLResult = &sqlProjection
			}
			if credentialFindings := returnedCredentialMaterialFindings(
				resolved.ReturnedCredentialSource,
				returnedCredentialMaterial,
			); len(credentialFindings) != 0 {
				// The proof is high confidence but intentionally advisory: post-tool
				// result hooks cannot prevent an operation that already completed.
				resp = mergeAgentHookFindings(
					profile, req, resp, credentialFindings, guardrailActionAllow,
				)
				eval := a.emitHookRuleFindings(
					ctx,
					req.ConnectorName,
					req.HookEventName,
					&ToolInspectVerdict{
						Action:           resp.Action,
						Severity:         HighestSeverity(credentialFindings),
						Findings:         FindingStrings(credentialFindings),
						DetailedFindings: credentialFindings,
					},
					"tool_result",
					latency,
				)
				if resp.EvaluationID == "" {
					resp.EvaluationID = eval.EvaluationID
				}
				resp.RuleIDs = mergeBoundedRuleIDs(
					8, eval.RuleIDs, resp.RuleIDs,
				)
			}
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
		a.decisionConfig(ctx),
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
			a.decisionConfig(ctx),
			req.ConnectorName,
			observationProjection,
		)
	}
	observeInput := audit.ToolChainObserveInput{
		SemanticEventID:     audit.SemanticEventID(req.SemanticEventID),
		ConnectorInstanceID: audit.ConnectorInstanceID(req.ConnectorInstanceID),
		InputFingerprint:    inputFingerprint,
		RulesetFingerprint:  rulesetFingerprint,
		Projection:          observationProjection,
		DenyEligible:        denyEligible,
	}
	if !resolvedSuccess && toolChainProjectionHasSteps(observationProjection) {
		result, err = repository.Observe(ctx, observeInput)
		if err != nil {
			if rootRepository != nil && !rootResolvedSuccess {
				rootMissed = "the leader did not take the step: " + err.Error()
			}
			return resp, finalization
		}
	}
	if rootRepository != nil && !rootResolvedSuccess && toolChainProjectionHasSteps(observationProjection) {
		if observed, rootErr := rootRepository.Observe(ctx, observeInput); rootErr == nil {
			rootResult = observed
		} else {
			rootMissed = "the leader did not take the step: " + rootErr.Error()
		}
	}
	rootAdded := rootToolChainAdded(profile, req, resp, rootRepository, rootResult, result, panicState)
	req.toolChain.noteChainEvidence(result, rootAdded)
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
		intent := substrateChainEgressIntent(ctx, toolChainHookIntent(
			guardrailActionForConnector(
				a.decisionConfig(ctx),
				req.ConnectorName,
				HighestSeverity(chainFindings),
				true,
			),
			denyEligible,
			result,
		), result)
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
		intent := substrateChainEgressIntent(ctx, toolChainHookIntent(
			guardrailActionForConnector(
				a.decisionConfig(ctx),
				req.ConnectorName,
				HighestSeverity(chainFindings),
				true,
			),
			denyEligible,
			result,
		), result)
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
	if slices.Contains(result.DetectedChainIDs, guardrail.ToolChainSecretReadThenEgress) &&
		!lifecycle.SupportsExactInvocationJoin() && !commandJoinConnector(ctx, req.ConnectorName) {
		// The read may be one no result could clear: say so (GAP-0338).
		resp.Reason = strings.TrimSpace(resp.Reason + " The " + unclearedReadWhy(req.ConnectorName) + ".")
	}
	if result.Status == audit.ToolChainObserveFresh &&
		len(result.ReceiptIDs) != 0 {
		finalization.repository = repository
		finalization.receiptIDs = append([]string(nil), result.ReceiptIDs...)
	}
	if rootRepository != nil {
		resp = a.applyToolChainRootResult(ctx, profile, req, resp, &finalization,
			rootRepository, rootResult, rootAdded, denyEligible, latency)
	}

	// A pre-tool proposal the gateway blocked keeps only its secret-read step
	// pending: a blocked call that never runs never promotes it, but one the
	// agent runs anyway (its exact success outcome arrives) is a completed
	// credentials read, and the egress after it is judged as the chain. The
	// strict tier blocks some credential-store reads outright (the tool-shape
	// path rules), and without this the read left no chain behind.
	pendingProjection := predecessorProjection
	preparePending := resp.Action != guardrailActionBlock
	if !preparePending {
		pendingProjection, preparePending = blockedSecretReadPredecessor(predecessorProjection)
	}
	if structuredAction &&
		preparePending &&
		invocationDigest != "" &&
		lifecycle.IsPreProposalEvent(req.HookEventName) {
		prepareInput := audit.ToolChainPreparePendingInput{
			ConnectorInstanceID:  audit.ConnectorInstanceID(req.ConnectorInstanceID),
			ToolInvocationDigest: invocationDigest,
			PreSemanticEventID:   audit.SemanticEventID(req.SemanticEventID),
			PreInputFingerprint:  inputFingerprint,
			RulesetFingerprint:   rulesetFingerprint,
			Projection:           pendingProjection,
		}
		if resp.Action != guardrailActionBlock {
			prepareInput.SQLValueSource = pendingSQLValueSource(req.toolChain)
			prepareInput.ReturnedCredentialSource = actionfacts.ExactReturnedCredentialSource(
				req.toolChain.facts,
			)
		}
		if rootRepository != nil {
			// Additive: a root-scope persistence failure changes nothing here.
			if _, rootErr := rootRepository.PreparePending(ctx, prepareInput); rootErr != nil {
				rootMissed = "the leader did not take the step: " + rootErr.Error()
			}
		}
		if _, prepareErr := repository.PreparePending(ctx, prepareInput); prepareErr != nil {
			// Pending state is an additive experimental lane. A persistence
			// failure must not replace the already-computed direct verdict.
			return resp, finalization
		}
	}
	return resp, finalization
}

// resultCallUnjoined reports a call result that no chain window joins (R1).
// The actor window, which the callout reads, decides when it is bound: its
// Missing is marked whatever the session says, so a session replay never
// hides it (review rk347 P3-1); a result after a turn boundary (Stop
// discards only the session's proposal) is joined there (GAP-0345); a
// further result of a resolved call is a replay in both (GAP-0348). A root
// call that failed is reported by the caller already.
func resultCallUnjoined(session audit.ToolChainPendingStatus, rootBound bool, root audit.ToolChainPendingStatus, rootFailed bool) bool {
	switch {
	case !rootBound:
		return session == audit.ToolChainPendingMissing
	case rootFailed:
		return false
	}
	rootJoined := root == audit.ToolChainPendingResolved || root == audit.ToolChainPendingReplay
	return root == audit.ToolChainPendingMissing || session == audit.ToolChainPendingMissing && !rootJoined
}

// substrateRegistrationNamesNoConnector reports a verified actor whose
// registration names no connector: an actor made outside DefenseClaw from an
// unattested template, or one the controller could not attest yet (GAP-0347,
// GAP-0351). Its binding resolves the empty hook profile, so the step's real
// reason is that, not the lifecycle.
func substrateRegistrationNamesNoConnector(ctx context.Context) bool {
	reg, ok := substrateRegistrationFrom(ctx)
	return ok && strings.TrimSpace(reg.Connector) == ""
}

// substrateChainUnrecordedRule is the finding of a Substrate actor's tool
// step that did not reach its actor window (GAP-0201).
const substrateChainUnrecordedRule = "SUBSTRATE-CHAIN-UNRECORDED"

// substrateUnrecordedTimeout bounds telling the leader of an unrecorded step.
const substrateUnrecordedTimeout = 2 * time.Second

// substrateChainWarned bounds the gateway log warning to one per actor and
// reason.
var substrateChainWarned sync.Map

// substrateChainUnrecorded answers a verified Substrate actor's tool step
// that can't reach the leader's actor window. The callout's egress check
// would not see it, so a secret read followed by an upload to an allowed
// host would pass: an alert finding on the hook, a warning in the gateway
// log, and a block when the connector's rule pack is strict (GAP-0201).
func (a *APIServer) substrateChainUnrecorded(ctx context.Context, profile connector.HookProfile, req agentHookRequest,
	resp agentHookResponse, latency time.Duration, why string) agentHookResponse {
	actor, ok := substrateActorFrom(ctx)
	if !ok {
		return resp
	}
	if _, seen := substrateChainWarned.LoadOrStore(actor.Atespace+"/"+actor.UID+"\x00"+why, true); !seen {
		fmt.Fprintf(os.Stderr, "[substrate] warning: %s/%s: a tool step is not in the actor's chain window, so the egress check can't link it: %s\n",
			actor.Atespace, actor.Name, why)
	}
	// The leader keeps it for the actor's egress checks: the callout refuses
	// a request checked against an incomplete window where it refuses
	// unchecked egress, and alerts elsewhere (GAP-0339). A leader that can't
	// be reached fails the egress check itself (the chain failure mode).
	if st := a.substrateState(); st != nil && st.cfg.Chains != nil {
		note := substrateNote{client: st.cfg.Chains, actor: chainstate.Actor{Atespace: actor.Atespace, UID: actor.UID}, why: why}
		if err := substrateNotes.deliver(ctx, note); err != nil {
			why += "; the leader was not told yet (retrying): " + err.Error()
		}
	}
	// Refused on a managed install and with a strict pack, an alert
	// elsewhere (refuse-by-default for what can't be checked, GAP-0339).
	intent := guardrailActionAlert
	if ManagedEnterpriseActive() || strictPackPosture(a.decisionConfig(ctx), req.ConnectorName) {
		intent = guardrailActionBlock
	}
	findings := []RuleFinding{{
		RuleID: substrateChainUnrecordedRule, Severity: "HIGH", Confidence: 1,
		Title:    "DefenseClaw could not record this tool call in the actor's chain window, so a later upload can't be checked against it",
		Evidence: why, Tags: []string{"substrate", "tool_call_chain"},
	}}
	resp = mergeAgentHookFindings(profile, req, resp, findings, intent)
	if !req.SuppressCorrelationEmit {
		eval := a.emitHookRuleFindings(ctx, req.ConnectorName, req.HookEventName, &ToolInspectVerdict{
			Action: resp.Action, Severity: "HIGH", Findings: FindingStrings(findings), DetailedFindings: findings,
		}, "tool_call_chain", latency)
		resp.RuleIDs = mergeBoundedRuleIDs(8, eval.RuleIDs, resp.RuleIDs)
	}
	return resp
}

// blockedSecretReadPredecessor is the secret-read steps of a blocked pre-tool
// proposal, with their own join digests and nothing else, or false when the
// proposal has none. Two steps: the secret-read chain, and the value-lineage
// chain whose step 1 the success result's value digests attach to
// (resolvePendingTx refuses a success that carries value digests when the
// pending row lacks that step, which lost the chain, GAP-0549).
func blockedSecretReadPredecessor(
	projection guardrail.ToolChainProjection,
) (guardrail.ToolChainProjection, bool) {
	out := guardrail.ToolChainProjection{ParseStatus: projection.ParseStatus}
	kept := false
	for _, id := range []string{
		guardrail.ToolChainSecretReadThenEgress,
		guardrail.ToolChainSensitiveReadValueExternalTransmit,
	} {
		bit, ok := guardrail.ToolChainStepMask(id, 1)
		index, indexed := guardrail.ToolChainIndexByID(id)
		if !ok || !indexed || projection.DetectionStepMask&bit == 0 {
			continue
		}
		kept = true
		out.DetectionStepMask |= bit
		out.EnforcementStepMask |= projection.EnforcementStepMask & bit
		out.EnforcementJoinDigests[index] = projection.EnforcementJoinDigests[index]
		out.EnforcementOutputJoinDigests[index] = projection.EnforcementOutputJoinDigests[index]
		out.ValueJoinDigests[index] = projection.ValueJoinDigests[index]
	}
	return out, kept
}

// toolChainProjectionForPolicyPosture keeps useful but proximity-only chain
// signals out of the normal blocking/alerting path. Privilege discovery
// followed by an elevated shell does not prove an exploit or unauthorized
// action without an exact principal, permission, and result join. Strict users
// may opt into that noisier signal; balanced and permissive users abstain.
func toolChainProjectionForPolicyPosture(
	cfg *config.Config,
	connectorName string,
	projection guardrail.ToolChainProjection,
) guardrail.ToolChainProjection {
	posture := ""
	if cfg != nil {
		ref := cfg.EffectiveRulePackRefForConnector(connectorName)
		posture = packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref))
	}
	return toolChainProjectionForNamedPosture(posture, projection)
}

func toolChainProjectionForNamedPosture(
	posture string,
	projection guardrail.ToolChainProjection,
) guardrail.ToolChainProjection {
	if posture == "strict" {
		return projection
	}
	// A proven secret-read-then-egress chain blocks only in strict; the
	// default and permissive tiers keep it as an alert (GAP-0595).
	if definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSecretReadThenEgress,
	); ok {
		projection.EnforcementStepMask &^= definition.Step1Bit | definition.Step2Bit |
			definition.Step3Bit | definition.Step4Bit | definition.MutationBit
	}

	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainPrivilegeDiscoveryThenElevation,
	)
	if !ok {
		return projection
	}
	mask := definition.Step1Bit | definition.Step2Bit | definition.Step3Bit |
		definition.Step4Bit | definition.MutationBit
	projection.DetectionStepMask &^= mask
	projection.EnforcementStepMask &^= mask
	if index, found := guardrail.ToolChainIndexByID(definition.ID); found {
		projection.EnforcementJoinDigests[index] = ""
		projection.EnforcementOutputJoinDigests[index] = ""
		projection.ValueJoinDigests[index] = guardrail.ToolChainValueJoinDigests{}
	}
	return projection
}

func splitToolChainProjection(
	projection guardrail.ToolChainProjection,
) (predecessor guardrail.ToolChainProjection, terminal guardrail.ToolChainProjection) {
	return splitToolChainProjectionForDefinitions(projection, guardrail.ToolChainDefinitions())
}

func splitToolChainProjectionForDefinitions(
	projection guardrail.ToolChainProjection,
	definitions []guardrail.ToolChainDefinition,
) (predecessor guardrail.ToolChainProjection, terminal guardrail.ToolChainProjection) {
	predecessor.ParseStatus = projection.ParseStatus
	terminal.ParseStatus = projection.ParseStatus
	predecessorMask := guardrail.ToolChainArtifactMutationBarrier
	var terminalMask uint64
	for index, definition := range definitions {
		if index >= guardrail.ToolChainCount {
			break
		}
		pendingMask := definition.Step1Bit
		if definition.RequiresTerminalSuccess {
			pendingMask |= definition.Step2Bit | definition.Step3Bit | definition.Step4Bit |
				definition.MutationBit
		} else {
			terminalMask |= definition.Step2Bit
		}
		predecessorMask |= pendingMask
		if projection.DetectionStepMask&pendingMask != 0 {
			predecessor.EnforcementJoinDigests[index] =
				projection.EnforcementJoinDigests[index]
		}
		if projection.DetectionStepMask&pendingMask != 0 {
			predecessor.ValueJoinDigests[index] = projection.ValueJoinDigests[index]
		}
		if !definition.RequiresTerminalSuccess &&
			projection.DetectionStepMask&definition.Step2Bit != 0 {
			terminal.EnforcementJoinDigests[index] =
				projection.EnforcementJoinDigests[index]
			terminal.ValueJoinDigests[index] = projection.ValueJoinDigests[index]
		}
		if definition.Step3Bit != 0 {
			predecessorMask |= definition.Step2Bit
			if !definition.RequiresTerminalSuccess && definition.Step4Bit == 0 {
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
		if definition.Step4Bit != 0 {
			predecessorMask |= definition.Step2Bit | definition.Step3Bit
			if !definition.RequiresTerminalSuccess {
				terminalMask |= definition.Step4Bit
			}
			if projection.DetectionStepMask&definition.Step1Bit != 0 {
				predecessor.EnforcementOutputJoinDigests[index] =
					projection.EnforcementOutputJoinDigests[index]
			}
			if projection.DetectionStepMask&(definition.Step2Bit|definition.Step3Bit) != 0 {
				predecessor.EnforcementJoinDigests[index] =
					projection.EnforcementJoinDigests[index]
				predecessor.EnforcementOutputJoinDigests[index] =
					projection.EnforcementOutputJoinDigests[index]
			}
			if projection.DetectionStepMask&definition.Step4Bit != 0 {
				if definition.RequiresTerminalSuccess {
					predecessor.EnforcementJoinDigests[index] =
						projection.EnforcementJoinDigests[index]
				} else {
					terminal.EnforcementJoinDigests[index] =
						projection.EnforcementJoinDigests[index]
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
	for index, digests := range source.ValueJoinDigests {
		if digests == (guardrail.ToolChainValueJoinDigests{}) {
			continue
		}
		if destination.ValueJoinDigests[index] == (guardrail.ToolChainValueJoinDigests{}) {
			destination.ValueJoinDigests[index] = digests
			continue
		}
		if destination.ValueJoinDigests[index] != digests {
			destination.ValueJoinDigests[index] = guardrail.ToolChainValueJoinDigests{}
		}
	}
}

func toolChainProjectionHasSteps(projection guardrail.ToolChainProjection) bool {
	return projection.DetectionStepMask != 0 || projection.EnforcementStepMask != 0
}

// exactToolChainInvocationDigest is the key that joins a tool call's result
// to its pre-tool proposal. A verified Substrate actor's proposal lives on
// the leader, and its result may reach another gateway replica than its
// call: each replica keys its correlation digests with its own HMAC key,
// derived from its own device key, so the key is the actor's own, not the
// replica's (substrate-1 GAP-0342). Elsewhere it stays the local
// correlation digest.
func exactToolChainInvocationDigest(
	ctx context.Context,
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
	if actor, ok := substrateActorFrom(ctx); ok {
		return substrateToolInvocationDigest(actor.Atespace, actor.UID, req.ConnectorName, req.SessionID, value)
	}
	return correlationValueDigest(
		audit.ConnectorInstanceID(req.ConnectorInstanceID),
		value,
	)
}

// substrateToolInvocationDigest is a verified actor's tool invocation key:
// the actor, its connector and session and the reported tool call id, the
// same on every gateway replica. The id is the agent's own random call id;
// the digest names it on the leader only.
func substrateToolInvocationDigest(atespace, uid, connectorName, sessionID string, value connector.CorrelationValue) string {
	digest := sha256.Sum256([]byte("defenseclaw/substrate/tool-invocation/v1\x00" + atespace + "\x00" + uid + "\x00" +
		normalizeConnectorNameForDigest(connectorName) + "\x00" + sessionID + "\x00" +
		typedCorrelationNamespace(value) + "\x00" + value.Value))
	return hex.EncodeToString(digest[:])
}

func normalizeConnectorNameForDigest(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
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
		steps := definition.Step1Bit | definition.Step2Bit | definition.Step3Bit |
			definition.Step4Bit
		if projection.EnforcementStepMask&steps != 0 &&
			guardrailActionForConnector(
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
		if guardrailActionForConnector(
			cfg,
			connectorName,
			definition.Severity,
			true,
		) == guardrailActionBlock {
			continue
		}
		projection.EnforcementStepMask &^=
			definition.Step1Bit | definition.Step2Bit | definition.Step3Bit |
				definition.Step4Bit
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
			// Preserve a committed chain denial or an earlier standalone block.
			// Every other incomplete evaluation answers the configured panic
			// fail mode instead of releasing the original allow.
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
				// A raw block may be only an observed policy verdict; only
				// Action proves the earlier response actually denies the call.
				if original.Action == guardrailActionBlock {
					resp = original
				} else {
					resp = a.hookPanicResponse(ctx, req.ConnectorName, req, rawBody, req.Payload)
				}
				finalization = toolChainHookFinalization{}
			}
		}
	}()
	hookStageForTest(ctx, "chain")
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
		projectToolValueLineageSink(
			&projection, capture.facts, activeToolValueLineageProcessKey,
		)
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
	projectADCSCertificateImpersonationChainSteps(projection, facts)
	projectKerberosS4UTicketSecretsDumpChainSteps(projection, facts)

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
		"secrets.structured_credential_extract",
		"secrets.browser_session_store_read",
		"secrets.workload_identity_token_read",
	}
	// A read of a credentials file starts the chain wherever the file is
	// (the home, a project, a work directory) and whether or not the active
	// pack alerts on the read itself: PATH-ENV-FILE is quiet in default and
	// the home-path rules name only the account's own copy
	// (substrate-1:GAP-0210).
	secretRead := hasAnyFinding(secretReadIDs...) || credentialFileContentRead(facts)
	secretReadDigest, secretReadIdentityExact := exactSecretReadChainDigest(facts)
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
		joinDigest := secretReadDigest
		if credentialFileReadDerivesFile(facts) {
			// The read's bytes also land in another file (a copy, a move, a
			// redirect, an archive): the file that is uploaded later may be
			// the source or the derived one (substrate-1:GAP-0388, GAP-0410).
			joinDigest = guardrail.ToolChainFileUnknownDigest
		}
		setToolChainEnforcementJoinDigest(
			projection,
			guardrail.ToolChainSecretReadThenEgress,
			joinDigest,
		)
	} else if facts.Parse.Status == actionfacts.StatusPartial ||
		facts.Parse.Status == actionfacts.StatusComplete && facts.HasCredentialPathReads() {
		// A pipeline or a command list the classifier cannot finish (an
		// unknown operand grammar in another stage) still proves a
		// credentials-file read when the reading command is complete: carry
		// the read's identity so the chain may start here, detection only
		// (guardrail Step1IdentityOwnsParseProof, substrate-1:GAP-0226).
		if digest, ok := credentialFileReadProofDigest(facts); ok {
			setToolChainEnforcementJoinDigest(
				projection,
				guardrail.ToolChainSecretReadThenEgress,
				digest,
			)
		}
	}
	if _, supported := toolValueLineageSourceKindForSensitiveRead(facts); supported {
		addToolChainStep(
			projection,
			guardrail.ToolChainSensitiveReadValueExternalTransmit,
			1,
			secretReadExact,
			secretReadExact,
		)
		if secretReadExact {
			setToolChainEnforcementJoinDigest(
				projection,
				guardrail.ToolChainSensitiveReadValueExternalTransmit,
				secretReadDigest,
			)
		}
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
	egressDetection := externalEgress || senderReaderEgress(facts) || hasAnyFinding(
		"CMD-WGET-POST",
		"CMD-CURL-UPLOAD",
		"exfil.secret_read_and_egress_oneliner",
	)
	egressEnforcement := externalEgress && facts.EnforcementEligible()
	// A sender the shared reader could not read in full (a function, trap or
	// coprocess body, interpreter code, a destination the shell builds) is the
	// unknown tier of the one bound rule for the secret-read chain: it joins
	// any exact credentials read and, with the strict pack's enforcement bits,
	// blocks (GAP-0672). The other two egress chains keep their own proofs.
	unknownSender := !egressEnforcement && senderReaderUnknownDestination(facts)
	for _, chainID := range []string{
		guardrail.ToolChainGuardrailsOffThenEgress,
		guardrail.ToolChainSecretManagerReadThenEgress,
		guardrail.ToolChainSecretReadThenEgress,
	} {
		chainEnforcement := egressEnforcement
		if chainID == guardrail.ToolChainSecretReadThenEgress {
			chainEnforcement = chainEnforcement && uploadIdentityExact
			if unknownSender {
				addToolChainStep(projection, chainID, 2, true, true)
				setToolChainEnforcementJoinDigest(
					projection, chainID, guardrail.ToolChainUnreadSenderDigest,
				)
				continue
			}
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
		} else if chainID == guardrail.ToolChainSecretReadThenEgress &&
			egressDetection && facts.Parse.Status == actionfacts.StatusPartial {
			// An upload inside a command list or a pipeline whose other parts
			// the classifier cannot finish: when every external upload command
			// is argv-complete, the upload is proven and the chain may end
			// here, detection only (guardrail Step2IdentityOwnsParseProof,
			// substrate-1:GAP-0389).
			if digest, ok := externalUploadProofDigest(facts); ok {
				setToolChainEnforcementJoinDigest(projection, chainID, digest)
			}
		}
	}

	projectFirewallTrustExpansionChainSteps(projection, facts)
	projectSQLServerCommandExecutionChainSteps(projection, facts)
	projectPrivilegedKubernetesChainSteps(projection, facts)
	projectWirelessCaptureDeauthChainSteps(projection, facts)
	projectCredentialRemoteExecutionChainSteps(projection, facts)
	projectCompromisedCredentialAuthenticationChainSteps(projection, facts)
	projectCloudIAMPrincipalAdminChainSteps(projection, facts)
	projectKubernetesPrivilegedCronJobChainSteps(projection, facts)
	projectSQLCommandUDFChainSteps(projection, facts)
	projectStagedReverseShellPersistenceChainSteps(projection, facts)
	projectEndpointSecurityControlChainSteps(projection, facts)
	projectSensitiveSQLiteReadDeleteChainSteps(
		projection,
		facts,
		hasAnyFinding(guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete) ||
			hasEnforceableFinding("impact.sql_unbounded_delete"),
	)
	projectStructuredFileEmailChainSteps(projection, facts)
	projectRemoteArtifactChainSteps(projection, facts)
	if factsMayMutateArtifact(facts) {
		projection.DetectionStepMask |= guardrail.ToolChainArtifactMutationBarrier
	}
}

func projectStructuredFileEmailChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainFileReadThenEmailSameArtifact
	if !facts.Authoritative() {
		return
	}
	if reads := actionfacts.ExactResourceReads(facts); len(reads) == 1 {
		addToolChainStep(projection, chainID, 1, true, false)
		setToolChainEnforcementJoinDigest(
			projection, chainID, reads[0].ResourceIdentityDigest,
		)
		return
	}
	transfers := actionfacts.ExactArtifactTransfers(facts)
	if len(transfers) != 1 || len(transfers[0].ArtifactIdentityDigests) != 1 {
		return
	}
	addToolChainStep(projection, chainID, 2, true, false)
	setToolChainEnforcementJoinDigest(
		projection, chainID, transfers[0].ArtifactIdentityDigests[0],
	)
}

func projectSensitiveSQLiteReadDeleteChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
	protectedDatabasePolicy bool,
) {
	const chainID = guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete
	if facts.Tool == "read_query" {
		reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
		if len(reads) != 1 || !reads[0].Exact || !facts.Authoritative() {
			return
		}
		digest := guardrail.ToolChainDatabaseTableJoinDigest(
			reads[0].DatabaseIdentityDigest,
			reads[0].TableIdentityDigest,
		)
		if digest == "" {
			return
		}
		// A structured read has no executable command and therefore is not
		// independently enforcement-eligible. It is only a pending proposal:
		// ResolvePending promotes the exact authenticated invocation after its
		// result reports success; failed and unknown outcomes discard it.
		addToolChainStep(projection, chainID, 1, true, false)
		setToolChainEnforcementJoinDigest(projection, chainID, digest)
		return
	}
	if facts.Tool != "write_query" {
		return
	}
	mutations := actionfacts.ExactSQLMutations(facts)
	if len(mutations) != 1 || !mutations[0].Exact ||
		mutations[0].Engine != "sqlite" ||
		mutations[0].QuerySource != actionfacts.SQLMutationQueryStructured ||
		mutations[0].Operation != actionfacts.SQLMutationDeleteUnbounded ||
		mutations[0].Scope != actionfacts.SQLMutationScopeTable ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return
	}
	digest := guardrail.ToolChainDatabaseTableJoinDigest(
		mutations[0].DatabaseIdentityDigest,
		mutations[0].ObjectIdentityDigest,
	)
	if digest == "" {
		return
	}
	// Detection is profile-independent. Enforcement is admitted only by a
	// shipped posture that explicitly treats this database scope as protected.
	addToolChainStep(projection, chainID, 2, true, protectedDatabasePolicy)
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
}

func projectKerberosS4UTicketSecretsDumpChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainS4UTicketThenKerberosSecretsdump
	if request, ok := actionfacts.ExactKerberosS4UTicketRequest(facts); ok {
		// Retain only the target's one-way identity until an authenticated result
		// proves that the same principal's cache was written. ResolvePending then
		// replaces this digest with the exact cache identity and promotes step one.
		addToolChainStep(projection, chainID, 1, true, false)
		setToolChainEnforcementJoinDigest(
			projection, chainID, request.TargetPrincipalIdentityDigest,
		)
		return
	}
	if sink, ok := actionfacts.ExactKerberosS4USecretsDumpSink(facts); ok {
		addToolChainStep(projection, chainID, 2, true, true)
		setToolChainEnforcementJoinDigest(
			projection, chainID, sink.TicketArtifactIdentityDigest,
		)
	}
}

func projectADCSCertificateImpersonationChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainADCSCertificateRequestThenPFXAuth
	if _, ok := actionfacts.ExactADCSCertificateImpersonationRequest(facts); ok {
		// The request is detection evidence immediately, but becomes enforcement
		// evidence only after its authenticated result proves the exact PFX that
		// was written. ResolvePending performs that promotion.
		addToolChainStep(projection, chainID, 1, true, false)
		return
	}
	if auth, ok := actionfacts.ExactADCSCertificateImpersonationAuth(facts); ok {
		addToolChainStep(projection, chainID, 2, true, true)
		setToolChainEnforcementJoinDigest(
			projection, chainID, auth.PFXArtifactIdentityDigest,
		)
	}
}

func projectCompromisedCredentialAuthenticationChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainCompromisedCredentialThenAuthenticate
	fact, ok := actionfacts.ExactCompromisedCredentialAuthentication(facts)
	if !ok || fact.AccountIdentityHMAC == "" || fact.CredentialValueHMAC == "" {
		return
	}
	definition, found := guardrail.ToolChainDefinitionByID(chainID)
	index, indexed := guardrail.ToolChainIndexByID(chainID)
	if !found || !indexed || definition.MutationBit == 0 {
		return
	}
	switch fact.Operation {
	case actionfacts.CompromisedCredentialRecorded:
		addToolChainStep(projection, chainID, 1, true, true)
		// A newer successful record for the same account invalidates any older
		// account/credential lineage before a later authentication result.
		projection.DetectionStepMask |= definition.MutationBit
		projection.EnforcementStepMask |= definition.MutationBit
	case actionfacts.CompromisedCredentialUsed:
		addToolChainStep(projection, chainID, 2, true, true)
	default:
		return
	}
	setToolChainEnforcementJoinDigest(
		projection, chainID, fact.AccountIdentityHMAC,
	)
	projection.ValueJoinDigests[index][0] = fact.CredentialValueHMAC
}

func projectEndpointSecurityControlChainSteps(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
) {
	const chainID = guardrail.ToolChainEndpointSecurityControlMutation
	operation, digest, ok := actionfacts.ExactEndpointSecurityControlLineageOperation(facts)
	if !ok || digest == "" {
		return
	}
	switch operation {
	case actionfacts.EndpointDefenderExclusionRequested,
		actionfacts.EndpointDefenderLoggingDisableRequested:
		addToolChainStep(projection, chainID, 1, true, false)
	case actionfacts.EndpointDefenderExclusionAdded,
		actionfacts.EndpointDefenderLoggingDisabled:
		addToolChainStep(projection, chainID, 2, true, false)
	default:
		return
	}
	setToolChainEnforcementJoinDigest(projection, chainID, digest)
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
		digest, exact := exactArtifactIntentPathDigest(downloaded)
		addToolChainStep(projection, directChainID, 1, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
		}
	} else if downloaded, ok := actionfacts.BoundedRemoteArtifactDownloadIntent(facts); ok {
		digest, exact := exactArtifactIntentPathDigest(downloaded)
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
		artifactDigest, artifactExact := exactArtifactIntentPathDigest(executed)
		addToolChainStep(projection, directChainID, 2, artifactExact, false)
		if artifactExact {
			setToolChainEnforcementJoinDigest(projection, directChainID, artifactDigest)
		}
		digest, exact := exactPathDigest(executed)
		addToolChainStep(projection, sensitiveEgressChainID, 2, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, sensitiveEgressChainID, digest)
		}
	} else if executed, ok := actionfacts.BoundedArtifactExecutionIntent(facts); ok {
		digest, exact := exactArtifactIntentPathDigest(executed)
		addToolChainStep(projection, directChainID, 2, exact, false)
		if exact {
			setToolChainEnforcementJoinDigest(projection, directChainID, digest)
		}
	}
}

// expectedRemoteDownload reports a call whose remote download (#1390) comes
// from a host under guardrail.internal_domains, or from a host that one of
// the user's recent prompts (this turn's or the two before it, as in
// "download X and run it" then "yes, go ahead") names together with a
// request to run, execute or install it: the only false positive of
// chain.download_then_execute_same_artifact in an external A/B run was such
// a download. userDownloadRequests records the prompts at the connector's
// turn-start event, with or without the LLM judge. Either can only lower
// this detection-only alert.
func (a *APIServer) expectedRemoteDownload(ctx context.Context, decision *config.Config, req agentHookRequest) bool {
	capture := req.toolChain
	if a == nil || capture == nil || !capture.recorded {
		return false
	}
	host, ok := actionfacts.RemoteArtifactDownloadIntentHost(capture.facts)
	if !ok {
		return false
	}
	if decision != nil && decision.Guardrail.IsInternalDomainHost(host) {
		return true
	}
	return a.userDownloads.requested(sandboxSessionStateKey(ctx, SessionIDFromContext(ctx)), host, time.Now())
}

// clearToolChainStep removes one step of chainID from the call's projection,
// and the chain's join digests when no other step of it is left.
func clearToolChainStep(projection *guardrail.ToolChainProjection, chainID string, step int) {
	bit, ok := guardrail.ToolChainStepMask(chainID, step)
	definition, found := guardrail.ToolChainDefinitionByID(chainID)
	index, indexed := guardrail.ToolChainIndexByID(chainID)
	if projection == nil || !ok || !found || !indexed {
		return
	}
	projection.DetectionStepMask &^= bit
	projection.EnforcementStepMask &^= bit
	if projection.DetectionStepMask&(definition.Step1Bit|definition.Step2Bit|definition.Step3Bit|
		definition.Step4Bit|definition.MutationBit) == 0 {
		projection.EnforcementJoinDigests[index] = ""
		projection.EnforcementOutputJoinDigests[index] = ""
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
	return guardrail.ToolChainPathIdentityDigest(identity), true
}

// exactArtifactIntentPathDigest is exactPathDigest for the artifact of a
// download or run intent of chain.download_then_execute_same_artifact
// (#1390). On a Windows host it also reads a Git Bash drive-letter spelling
// (C:/x or C:\x, which the POSIX reading leaves relative) as that drive
// file, so it joins the same file spelled /c/x or C:\x
// (rel-1-0-6:GAP-0182). Other chains keep exactPathDigest.
func exactArtifactIntentPathDigest(candidate actionfacts.PathFact) (string, bool) {
	if identity, ok := gitBashDriveLetterIdentity(candidate); ok {
		return guardrail.ToolChainPathIdentityDigest("windows\x00" + identity), true
	}
	return exactPathDigest(candidate)
}

// gitBashDriveLetterIdentity is the Windows identity (lower case, forward
// slashes, as gitBashDriveIdentity) of a POSIX-shell operand spelled with a
// drive letter, or of a relative operand the intent placed under the call's
// Windows directory, on a Windows host only; elsewhere C:/x is a relative
// path.
func gitBashDriveLetterIdentity(candidate actionfacts.PathFact) (string, bool) {
	value := candidate.Value
	if !actionfacts.DriveLetterPath(value) && actionfacts.DriveLetterPath(candidate.Resolved) {
		// A relative operand placed under the call's Windows directory
		// (rel-1-0-6:GAP-0212).
		value = candidate.Resolved
	}
	if !toolChainDriveMounts || candidate.Flavor != actionfacts.PathFlavorPOSIX ||
		!actionfacts.DriveLetterPath(value) || strings.ContainsRune(value, '\x00') {
		return "", false
	}
	return strings.ToLower(value[:2] + path.Clean(strings.ReplaceAll(value[2:], `\`, "/"))), true
}

// credentialFileContentRead reports an executed command that reads,
// searches (grep) or copies the contents of a file of a credentials-file shape
// (actionfacts.MatchCredentialFileShape, the one table) anywhere the agent
// can reach. Not counted: a repository fixture (credentialFileFixturePath)
// and an SSH client that only presents a key (ssh -i, scp -i), which
// PATH-SSH-KEY does not count either.
func credentialFileContentRead(facts actionfacts.Facts) bool {
	for _, candidate := range facts.CredentialPathReads() {
		if !credentialFileFixturePath(semanticPathValue(candidate)) {
			return true
		}
	}
	for _, candidate := range facts.Paths {
		if _, ok := credentialFileContentReadCommand(facts, candidate); ok {
			return true
		}
	}
	return false
}

// credentialFileContentReadCommand returns the command that reads the
// contents of candidate when candidate is a credentials-file read that
// credentialFileContentRead counts.
func credentialFileContentReadCommand(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) (actionfacts.CommandFact, bool) {
	if candidate.Access != actionfacts.PathAccessRead {
		return actionfacts.CommandFact{}, false
	}
	value := semanticPathValue(candidate)
	if _, ok := actionfacts.MatchCredentialFileShape(value); !ok ||
		credentialFileFixturePath(value) {
		return actionfacts.CommandFact{}, false
	}
	command, ok := integrityCommandByID(facts, candidate.CommandID)
	if !ok || command.Effect != actionfacts.EffectExecute ||
		sshIdentityConsumer(command) && command.Program != "rsync" ||
		!hasAnyOperation(command, actionfacts.OperationRead,
			actionfacts.OperationSearch, actionfacts.OperationCopy) {
		// rsync is no key consumer here: its local sources are copied, and
		// its remote operands carry no path fact.
		return actionfacts.CommandFact{}, false
	}
	return command, true
}

// credentialFileReadDerivesFile reports a call that reads a credentials
// file and also writes, appends, copies, moves or links any file anywhere in
// the call: in any pipeline stage or list member, by any redirect kind (>,
// >>, >|, an fd opened by exec), by tee, dd, an archiver, rsync, cp, mv or
// ln. The read's bytes may be in that file, so a later upload of it joins
// the read: the read carries the file-unknown marker instead of its own
// identity (GAP-0410). It errs towards the marker: an unrelated write in the
// same call gives the marker too, which only joins more.
func credentialFileReadDerivesFile(facts actionfacts.Facts) bool {
	if !credentialFileContentRead(facts) {
		return false
	}
	return callWritesAnyFile(facts)
}

// callWritesAnyFile reports a write, an append, a copy, a move or a link of a
// file by any command of the call: by its own operands (cp, mv, ln, install,
// dd, tee, an archiver, rsync, an -o writer) or by its redirects (>, >>, >|,
// an fd opened by exec). A redirect to the null device or to another
// descriptor, and a redirect of stderr (fd 2) to a file in a command that
// duplicates no descriptor, write no file the call's bytes reach. The
// classifier still gives the command a write op and a write path for it, so
// both are set aside for such a redirect (GAP-0479).
func callWritesAnyFile(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if hasAnyOperation(command, actionfacts.OperationCopy, actionfacts.OperationMove,
			actionfacts.OperationDiskWrite) {
			return true
		}
		switch command.Program {
		case "tee", "ln", "link", "install", "dd":
			return true
		}
		quietRedirect := false
		for _, redirect := range command.Redirects {
			if !writesFile(redirect.Access) {
				continue
			}
			if redirectWritesNoFile(command, redirect) {
				quietRedirect = true
				continue
			}
			return true
		}
		if !quietRedirect &&
			hasAnyOperation(command, actionfacts.OperationWrite, actionfacts.OperationAppend) {
			return true
		}
	}
	for _, candidate := range facts.Paths {
		if writesFile(candidate.Access) && !quietRedirectTarget(facts, candidate) {
			return true
		}
	}
	return false
}

func writesFile(access actionfacts.PathAccess) bool {
	return access == actionfacts.PathAccessWrite || access == actionfacts.PathAccessAppend
}

// wordsMayNameDerivedSource reports a command whose words, not its path
// facts, may name the source of a derived file: the target of a link (ln -s
// records no path for it), or an operand the classifier does not model (gzip
// -c .env records no read) of a command that writes its output to a file or
// into a pipeline. A command that has a read path, echo and printf (they
// print their words) are not tested: a pattern (grep -q .env), an exclusion
// (tar --exclude=.env) or an ignore entry (echo .env >> .gitignore) derives
// nothing (GAP-0479).
func wordsMayNameDerivedSource(facts actionfacts.Facts, command actionfacts.CommandFact) bool {
	switch command.Program {
	case "echo", "printf":
		return false
	}
	for _, candidate := range facts.Paths {
		if candidate.CommandID == command.ID && candidate.Access == actionfacts.PathAccessRead {
			return false
		}
	}
	switch command.Program {
	case "ln", "link":
		return true
	}
	if command.PipelineID != 0 {
		return true
	}
	for _, redirect := range command.Redirects {
		if (redirect.FD == 1 || redirect.FD == -1) && writesFile(redirect.Access) &&
			!redirectWritesNoFile(command, redirect) {
			return true
		}
	}
	return false
}

// redirectWritesNoFile reports a redirect of command to the null device or
// to another descriptor (>&3, 2>&1), or of its stderr to a file when the
// command duplicates no descriptor: with >&2 the output reaches the stderr
// file too.
func redirectWritesNoFile(command actionfacts.CommandFact, redirect actionfacts.RedirectFact) bool {
	if redirectDuplicatesDescriptor(redirect) || redirect.Target == "/dev/null" {
		return true
	}
	if redirect.FD != 2 {
		return false
	}
	for _, other := range command.Redirects {
		if redirectDuplicatesDescriptor(other) {
			return false
		}
	}
	return true
}

func redirectDuplicatesDescriptor(redirect actionfacts.RedirectFact) bool {
	return redirect.Target == "" || strings.HasPrefix(redirect.Target, "&")
}

// quietRedirectTarget reports a written path that is the null device or the
// target of a redirectWritesNoFile redirect of its own command.
func quietRedirectTarget(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
	if candidate.Value == "/dev/null" {
		return true
	}
	command, ok := integrityCommandByID(facts, candidate.CommandID)
	if !ok {
		return false
	}
	for _, redirect := range command.Redirects {
		if redirect.Target == candidate.Value && writesFile(redirect.Access) &&
			redirectWritesNoFile(command, redirect) {
			return true
		}
	}
	return false
}

// uploadCallDerivesCredentialFile reports an upload call that also copies,
// moves, links, archives or redirects a credentials file to a new name: a
// command other than the uploaders (uploads, by command ID) takes a file of
// a credentials-file shape or a file a secret-read rule names
// (matchesAnySensitivePathCandidate; not a repository fixture) as a path, or
// as a word where no path is recorded (wordsMayNameDerivedSource), and the
// call writes a file (callWritesAnyFile). The file it
// uploads may be that copy, so the upload names no one file (GAP-0445). Any
// other write in an upload call (a response redirect, -o, a log tee, a
// build archive, a stamp file) leaves the uploaded file named, so an upload
// of a different, known file does not complete the chain (GAP-0479).
func uploadCallDerivesCredentialFile(facts actionfacts.Facts, uploads map[int64]struct{}) bool {
	if !callWritesAnyFile(facts) {
		return false
	}
	source := func(command actionfacts.CommandFact, value string) bool {
		if _, upload := uploads[command.ID]; upload || command.Effect != actionfacts.EffectExecute ||
			sshIdentityConsumer(command) && command.Program != "rsync" {
			return false
		}
		return matchesAnySensitivePathCandidate(value) && !credentialFileFixturePath(value)
	}
	for _, candidate := range facts.Paths {
		if writesFile(candidate.Access) {
			continue
		}
		if command, ok := integrityCommandByID(facts, candidate.CommandID); ok &&
			source(command, semanticPathValue(candidate)) {
			return true
		}
	}
	for _, command := range facts.Commands {
		if !wordsMayNameDerivedSource(facts, command) {
			continue
		}
		for _, argument := range command.Argv[min(1, len(command.Argv)):] {
			if !strings.HasPrefix(argument, "-") && source(command, argument) {
				return true
			}
		}
	}
	return false
}

// directoryKeepingPrograms are the programs, besides the reader table, that
// cannot change the directory the next command runs in: external programs
// the chain reads or sends with, and the shell builtins that only print or
// test. A cd, pushd, popd, source, `.`, eval, trap, alias, a function call or
// any program not named here is not proven (GAP-0418). tar is not named: -C,
// a bundled -cC, --directory, --dir= and bsdtar --cd move its members. awk is
// named only because the reader records an awk read solely for a plain print
// program with no options: a gawk -f, -i, -l or @load script can chdir()
// before awk opens its operand, so keep that restriction.
var directoryKeepingPrograms = map[string]struct{}{
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {}, "grep": {}, "egrep": {}, "fgrep": {},
	"rg": {}, "uniq": {}, "tr": {}, "wc": {}, "base64": {}, "openssl": {}, "sed": {}, "awk": {},
	"cp": {}, "mv": {}, "ln": {}, "rm": {}, "mkdir": {}, "touch": {}, "tee": {}, "dd": {}, "install": {},
	"zip": {}, "unzip": {}, "gzip": {}, "gunzip": {}, "bzip2": {}, "xz": {},
	"rsync": {}, "scp": {}, "curl": {}, "wget": {}, "jq": {}, "yq": {}, "find": {}, "ls": {}, "stat": {}, "file": {},
	"echo": {}, "printf": {}, "true": {}, "false": {}, ":": {}, "test": {}, "[": {}, "sleep": {}, "date": {},
	"pwd": {}, "whoami": {}, "id": {}, "uname": {}, "hostname": {},
}

// callProvenToKeepDirectory reports a call proven not to change the
// directory its commands run in: a complete parse in which every command is a
// known program that cannot change it (the reader table, an upload or copy
// tool, a printing builtin). Anything
// else (a function or alias the call defines, `.`, `source`, `eval`, `trap`,
// an unknown program that may be a function of the agent's shell, a call the
// parser cannot finish) is not proven: a relative operand in it is unnamed and
// the chain joins on the marker (GAP-0418).
func callProvenToKeepDirectory(facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusComplete {
		return false
	}
	for _, command := range facts.Commands {
		program := command.Program
		if _, ok := directoryKeepingPrograms[program]; ok || actionfacts.StandardFileReaderProgram(program) {
			continue
		}
		return false
	}
	return true
}

// secretReadPathIdentity is exactPathIdentity, except that a relative
// operand is an exact file only when the call is PROVEN not to change
// directory (callProvenToKeepDirectory): the path fact keeps the call's
// starting directory, not the one the commands ran in (GAP-0409, GAP-0418).
func secretReadPathIdentity(facts actionfacts.Facts, candidate actionfacts.PathFact) (string, bool) {
	if !candidate.Absolute && !callProvenToKeepDirectory(facts) {
		return "", false
	}
	return exactPathIdentity(candidate)
}

// exactSecretReadChainDigest is exactSingleReadPathDigest for the
// secret-read chain: the identity of a relative operand in a call that may
// change directory is not exact (GAP-0409).
//
// The call's own paths and then the chain's private reads are checked one at
// a time, and the digest is refused at the first read whose identity is not
// exact or differs from the one before: every later read can only agree or
// refuse again. A call that searches a deep tree has hundreds of private
// reads, and each is spelled by a Windows system call; the handler kept the
// call's whole record alive until it had spelled them all (substrate-1:
// GAP-0674). secretReadPathIdentity reads the call's commands and the read
// itself, never the call's other paths, so the checks do not depend on the
// order.
func exactSecretReadChainDigest(facts actionfacts.Facts) (string, bool) {
	var selected string
	exact := func(candidate actionfacts.PathFact) bool {
		identity, ok := secretReadPathIdentity(facts, candidate)
		if !ok || selected != "" && selected != identity {
			return false
		}
		selected = identity
		return true
	}
	for _, candidate := range facts.Paths {
		if candidate.Access == actionfacts.PathAccessRead &&
			matchesAnySensitivePathCandidate(semanticPathValue(candidate)) && !exact(candidate) {
			return "", false
		}
	}
	for _, candidate := range facts.CredentialPathReads() {
		value := semanticPathValue(candidate)
		if credentialFileFixturePath(value) {
			continue
		}
		if candidate.Value == "" {
			return "", false
		}
		if candidate.Access == actionfacts.PathAccessRead && matchesAnySensitivePathCandidate(value) && !exact(candidate) {
			return "", false
		}
	}
	if selected == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte("defenseclaw/tool-chain/path-identity/v1\x00" + selected))
	return hex.EncodeToString(digest[:]), true
}

// externalUploadProofDigest proves an external upload in a call whose
// overall parse is partial: every command that uploads to an external
// destination has its argv complete. The digest is the uploaded file's
// identity when the uploads read one exact file, else the
// guardrail.ToolChainFileUnknownDigest marker (a stdin upload, several
// files).
func externalUploadProofDigest(facts actionfacts.Facts) (string, bool) {
	uploads := make(map[int64]struct{})
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationUpload) ||
			!hasExternalUpload(facts, command.ID) {
			continue
		}
		if !command.ArgvComplete {
			return "", false
		}
		uploads[command.ID] = struct{}{}
	}
	if len(uploads) == 0 {
		return "", false
	}
	if uploadCallDerivesCredentialFile(facts, uploads) {
		// The upload call derives a file from a credentials file: it names
		// no one file (GAP-0445, GAP-0479).
		return guardrail.ToolChainFileUnknownDigest, true
	}
	selected, exact := "", true
	for _, candidate := range facts.Paths {
		if _, ok := uploads[candidate.CommandID]; !ok || candidate.Access != actionfacts.PathAccessRead {
			continue
		}
		identity, ok := secretReadPathIdentity(facts, candidate)
		if !ok || selected != "" && selected != identity {
			exact = false
			continue
		}
		selected = identity
	}
	if exact && selected != "" {
		return guardrail.ToolChainPathIdentityDigest(selected), true
	}
	return guardrail.ToolChainFileUnknownDigest, true
}

// credentialFileReadProofDigest proves a credentials-file read in a call
// whose overall parse is partial: every command that reads a
// credentials-shaped file (credentialFileContentReadCommand) has its argv
// complete, whatever the other stages of the pipeline or members of the list
// are. A member of an && or || list runs conditionally; the step is
// detection-only, so that is enough. The digest is the read file's exact
// identity when there is one file (a relative path joined to the call's
// directory when the hook cannot resolve it) and it is not copied or moved,
// else the guardrail.ToolChainFileUnknownDigest marker, which joins any upload
// (substrate-1:GAP-0388).
func credentialFileReadProofDigest(facts actionfacts.Facts) (string, bool) {
	selected, found, exact := "", false, true
	private := facts.CredentialPathReads()
	for _, candidate := range private {
		if credentialFileFixturePath(semanticPathValue(candidate)) {
			continue
		}
		found = true
		identity, ok := secretReadPathIdentity(facts, candidate)
		if !ok || selected != "" && selected != identity {
			exact = false
			// Nothing after a read that is not exact changes the result: the
			// call has a read, and none of the reads is a single exact file.
			// The rest are spelled by a system call each on Windows, with the
			// call's record kept alive (substrate-1:GAP-0674).
			break
		}
		selected = identity
	}
	for _, candidate := range facts.Paths {
		command, ok := credentialFileContentReadCommand(facts, candidate)
		if !ok {
			continue
		}
		if !command.ArgvComplete {
			if len(private) == 0 {
				return "", false
			}
			// A word the call computes may name another file: the record
			// proves a read, not which one.
			exact = false
		}
		found = true
		identity, ok := secretReadPathIdentity(facts, candidate)
		if !ok || selected != "" && selected != identity {
			exact = false
			continue
		}
		selected = identity
	}
	switch {
	case !found:
		return "", false
	case exact && selected != "" && !credentialFileReadDerivesFile(facts):
		return guardrail.ToolChainPathIdentityDigest(selected), true
	default:
		return guardrail.ToolChainFileUnknownDigest, true
	}
}

// credentialFileFixturePath reports a credentials-shaped file inside a
// repository's test or documentation tree, or inside an installed
// third-party package, which ship sample keys and .env files (owner traces,
// substrate-1:GAP-0210).
func credentialFileFixturePath(value string) bool {
	if integrityPathHasFixtureSegment(value) {
		return true
	}
	for _, component := range strings.Split(strings.Trim(canonicalSemanticPath(value), "/"), "/") {
		switch component {
		case "node_modules", "site-packages", "dist-packages":
			return true
		}
	}
	return false
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
	if uploadCallDerivesCredentialFile(facts, externalUploadCommands) {
		// The upload call itself copies, moves, links, archives or redirects a
		// credentials file to a new name: the file it uploads may be that
		// copy, so it names no one file (GAP-0445, the upload-side twin of
		// GAP-0410; GAP-0479 keeps any other write out of it).
		return "", false
	}
	return exactSinglePathDigestBy(facts, func(candidate actionfacts.PathFact) bool {
		_, uploadCommand := externalUploadCommands[candidate.CommandID]
		return uploadCommand && candidate.Access == actionfacts.PathAccessRead
	}, secretReadPathIdentity)
}

func exactSinglePathDigest(
	facts actionfacts.Facts,
	selectPath func(actionfacts.PathFact) bool,
) (string, bool) {
	return exactSinglePathDigestBy(facts, selectPath, func(_ actionfacts.Facts, candidate actionfacts.PathFact) (string, bool) {
		return exactPathIdentity(candidate)
	})
}

func exactSinglePathDigestBy(
	facts actionfacts.Facts,
	selectPath func(actionfacts.PathFact) bool,
	identityOf func(actionfacts.Facts, actionfacts.PathFact) (string, bool),
) (string, bool) {
	var selected string
	for _, candidate := range facts.Paths {
		if !selectPath(candidate) {
			continue
		}
		identity, ok := identityOf(facts, candidate)
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
		if drive, ok := gitBashDriveIdentity(resolved); ok {
			return "windows\x00" + drive, true
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

// toolChainDriveMounts is set on Windows, where Git Bash names drive C: as
// /c (or /C): there a POSIX path under a one-letter mount is the drive path.
var toolChainDriveMounts = runtime.GOOS == "windows"

// gitBashDriveIdentity is the Windows identity (drive letter and path, lower
// case, forward slashes) of a Git Bash drive-mount path such as
// /c/Users/u/page.txt on a Windows host, so a tool chain joins the same file
// spelled /c/..., /C/... or C:\... as one path (rel-1-0-6:GAP-0173). Windows
// file names are case-insensitive, as for PathFlavorWindows. ok is false off
// Windows and for any other POSIX path.
func gitBashDriveIdentity(resolved string) (string, bool) {
	if !toolChainDriveMounts || len(resolved) < 2 || resolved[0] != '/' {
		return "", false
	}
	letter := resolved[1]
	if (letter < 'a' || letter > 'z') && (letter < 'A' || letter > 'Z') ||
		len(resolved) > 2 && resolved[2] != '/' {
		return "", false
	}
	rest := ""
	if len(resolved) > 3 {
		rest = resolved[3:]
	}
	return strings.ToLower(string(letter) + ":/" + rest), true
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

// senderReaderEgress reports a sender the shared sender reader
// (actionfacts.ReadSenders) finds beyond the upload facts
// externalDataBearingUpload reads, or one whose destination it cannot read:
// a remote copy (rsync, sftp), a program a find -exec or an xargs runs, a
// sender in a shell part the projection did not read, an upload to a host
// the shell builds (GAP-0597, GAP-0598, GAP-0599). It sends to an external
// host, or to a destination that is not read (never "no sender"). It detects
// the egress step only: an enforcement proof needs the exact upload.
func senderReaderEgress(facts actionfacts.Facts) bool {
	for _, sender := range actionfacts.ReadSenders(facts).Senders {
		if sender.DestinationUnknown {
			return true
		}
		if sender.Origin == actionfacts.SenderProjected {
			continue // externalDataBearingUpload reads it
		}
		for _, network := range sender.Network {
			if isExternalNetwork(network) {
				return true
			}
		}
	}
	return false
}

// senderReaderUnknownDestination reports a call the shared sender reader
// cannot prove sends nothing: a sender whose destination it cannot read in
// full, a part it cannot read (a program word the shell builds, a source the
// parser gave up on) or a reading cap (never "no sender").
func senderReaderUnknownDestination(facts actionfacts.Facts) bool {
	return actionfacts.ReadSenders(facts).UnknownTier()
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

func projectToolValueLineageSink(
	projection *guardrail.ToolChainProjection,
	facts actionfacts.Facts,
	processKey toolValueLineageProcessKey,
) {
	if projection == nil || !processKey.available ||
		facts.Parse.Status != actionfacts.StatusComplete ||
		!facts.Authoritative() || !facts.EnforcementEligible() ||
		!externalDataBearingUpload(facts) || len(facts.Commands) != 1 {
		return
	}
	digests, ok := toolValueLineageCurlPayloadDigests(
		processKey.material, facts.Commands[0],
	)
	if !ok {
		return
	}
	values := toolValueLineageGuardrailDigests(digests)
	if values == (guardrail.ToolChainValueJoinDigests{}) {
		return
	}
	addToolChainStep(
		projection,
		guardrail.ToolChainSensitiveReadValueExternalTransmit,
		2,
		true,
		true,
	)
	index, ok := guardrail.ToolChainIndexByID(
		guardrail.ToolChainSensitiveReadValueExternalTransmit,
	)
	if ok {
		projection.ValueJoinDigests[index] = values
	}
}

func toolValueLineageSuccessfulReadResult(
	ctx context.Context,
	req agentHookRequest,
	outcome connector.ToolLifecycleOutcome,
) (string, guardrail.ToolChainValueJoinDigests) {
	if !activeToolValueLineageProcessKey.available ||
		outcome != connector.ToolLifecycleOutcomeSuccess ||
		!strings.EqualFold(req.ConnectorName, "claudecode") ||
		canonicalEvent(req.HookEventName) != "posttooluse" {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	toolInput, ok := req.Payload["tool_input"].(map[string]interface{})
	if !ok || len(toolInput) == 0 {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	response, ok := req.Payload["tool_response"].(string)
	if !ok || req.Payload["tool_calls"] != nil ||
		strings.TrimSpace(payloadString(req.Payload, "error")) != "" ||
		strings.TrimSpace(payloadString(req.Payload, "error_details")) != "" {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	args, err := json.Marshal(toolInput)
	if err != nil {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:       req.ToolName,
		Args:       args,
		CWD:        req.CWD,
		ActiveHome: hookActiveHome(ctx),
	})
	pathDigest, exact := exactSingleReadPathDigest(facts)
	kind, supported := toolValueLineageSourceKindForSensitiveRead(facts)
	if !exact || !supported || facts.Parse.Status != actionfacts.StatusComplete ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	digests, ok := toolValueLineageSourceDigests(
		activeToolValueLineageProcessKey.material, kind, []byte(response),
	)
	if !ok {
		return "", guardrail.ToolChainValueJoinDigests{}
	}
	return pathDigest, toolValueLineageGuardrailDigests(digests)
}

func toolValueLineageSourceKindForSensitiveRead(
	facts actionfacts.Facts,
) (toolValueLineageSourceKind, bool) {
	var selected string
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessRead ||
			!matchesAnySensitivePathCandidate(semanticPathValue(candidate)) {
			continue
		}
		identity, ok := exactPathIdentity(candidate)
		if !ok || (selected != "" && selected != identity) {
			return 0, false
		}
		selected = identity
	}
	if selected == "" {
		return 0, false
	}
	value := strings.ToLower(strings.ReplaceAll(selected, `\`, "/"))
	// An identity is "<flavor>\x00<path>"; the credentials-file table reads
	// the path (it refuses a value with a NUL byte).
	if index := strings.LastIndexByte(value, 0); index >= 0 {
		value = value[index+1:]
	}
	switch {
	case matchesEnvironmentFile(value) || matchesProcEnvironCandidate(value):
		return toolValueLineageSourceEnv, true
	case strings.HasSuffix(value, ".json"):
		return toolValueLineageSourceJSON, true
	case matchesSSHPrivateKey(value):
		return toolValueLineageSourcePEM, true
	case matchesWorkloadIdentityTokenCandidate(value):
		return toolValueLineageSourceSingleToken, true
	default:
		return 0, false
	}
}

func toolValueLineageGuardrailDigests(
	digests []toolValueLineageDigest,
) guardrail.ToolChainValueJoinDigests {
	var result guardrail.ToolChainValueJoinDigests
	if len(digests) == 0 || len(digests) > len(result) {
		return result
	}
	for index, digest := range digests {
		result[index] = hex.EncodeToString(digest[:])
	}
	return result
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
	next.SuppressNotification = resp.SuppressNotification
	next.aiDefenseEnforced = resp.aiDefenseEnforced && next.Action == "block"
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
	next.SuppressNotification = resp.SuppressNotification
	next.aiDefenseEnforced = resp.aiDefenseEnforced && next.Action == "block"
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
			// Recovery has no verified caller home. Never send the gateway
			// service account's watch paths to a managed agent.
			claudeCodeHookRequest{HookEventName: req.HookEventName, PermissionMode: payloadString(req.Payload, "permission_mode"), managedWatch: true, watchHome: unresolvedCallerHome},
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

// toolChainRulesetFingerprint is activeToolChainRulesetFingerprint; a test
// replaces it to prove what a failed read does.
var toolChainRulesetFingerprint = activeToolChainRulesetFingerprint

func activeToolChainRulesetFingerprint(
	ctx context.Context,
	connectorName string,
	profile connector.HookProfile,
) (string, error) {
	generation := pinnedRuleGeneration(ctx, connectorName)
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

// resultMayBeAnUnjoinedRead reports a tool result whose own call may have
// been a credentials read: its projection holds the secret-read step, its
// tool input reads a credentials file (a result event runs no pre-tool rule
// dispatch, so its facts are read here), or it names no tool to tell (R1).
// A plain call (ls) does not.
func resultMayBeAnUnjoinedRead(req agentHookRequest, projection guardrail.ToolChainProjection) bool {
	if bit, ok := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1); ok && projection.DetectionStepMask&bit != 0 {
		return true
	}
	if strings.TrimSpace(req.ToolName) == "" {
		return true
	}
	return credentialFileContentRead(actionfacts.Analyze(actionfacts.Input{Tool: req.ToolName, Args: req.ToolArgs, CWD: req.CWD}))
}

// The secret-read chain start (owner decision 2026-11-13; substrate-1
// GAP-0337, GAP-0338). A tool call that reads a credentials file starts
// chain.secret_read_then_egress unless DefenseClaw proves it read nothing,
// whatever its exit code and whatever the connector:
//   - a call whose result is tied to it (a paired tool invocation id) keeps
//     the read as a pending proposal. Its result decides by what it printed:
//     a success, or a failed or unknown result that toolResultProvesNothingRead
//     does not clear, promotes it (ResolvePending, UnsuccessfulMayHaveRead);
//     a denied or cancelled call never ran;
//   - a Devin or Copilot call of a verified Substrate actor (no invocation
//     id, but a result with the call's command and output) is kept pending
//     under the command join and decided by its result the same way
//     (GAP-0340, commandJoinDigest);
//   - any other call whose result cannot be tied to it (Antigravity's step
//     index, Kiro, those connectors off Substrate, or a call that carries
//     none) starts the chain at the proposal (withSecretReadStart): no result
//     will say what it printed, so nothing can clear it.
// Both keep the read's step 1 alone (guardrail.ToolChainProjectionStep).

// withSecretReadStart adds the secret-read step 1 of a proposal's
// predecessor projection to its observation. A call that also uploads keeps
// the one join identity the projection has for the chain.
func withSecretReadStart(observation, predecessor guardrail.ToolChainProjection) guardrail.ToolChainProjection {
	start, ok := guardrail.ToolChainProjectionStep(predecessor, guardrail.ToolChainSecretReadThenEgress, 1)
	if !ok {
		return observation
	}
	index, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	observation.DetectionStepMask |= start.DetectionStepMask
	observation.EnforcementStepMask |= start.EnforcementStepMask
	if observation.EnforcementJoinDigests[index] == "" {
		observation.EnforcementJoinDigests[index] = start.EnforcementJoinDigests[index]
	}
	if observation.EnforcementOutputJoinDigests[index] == "" {
		observation.EnforcementOutputJoinDigests[index] = start.EnforcementOutputJoinDigests[index]
	}
	if observation.ParseStatus == "" {
		observation.ParseStatus = start.ParseStatus
	}
	return observation
}

// unclearedReadWhy says why a connector's credentials read started the
// secret-read chain at its proposal (GAP-0338).
func unclearedReadWhy(connectorName string) string {
	return "credentials read could not be cleared: no result correlation for " + connectorName
}

// The command join (substrate-1 GAP-0340). Devin and Copilot name no tool
// invocation, but their result event carries the call's own tool name and
// arguments (Devin PostToolUse tool_input with tool_response; Copilot
// postToolUse and postToolUseFailure toolArgs with toolResult). For a
// verified Substrate actor, a credentials read of theirs is kept pending
// under a key of the actor, connector, session, tool and exact arguments
// instead of starting the chain at the proposal, and its result decides by
// what it printed: one that proves nothing was read
// (toolResultProvesNothingRead) clears it, any other promotes it. The
// pending read counts at the callout from the proposal on, as a paired
// call's does. When the key can't be made (no session, no tool, arguments
// that are the hook envelope or uncertain) or the leader does not take the
// pending read, the chain starts at the proposal as before. Antigravity
// (a step index, no command on the result) and Kiro (no output) stay as
// they are, and so does the host path.

// commandJoinConnector reports a connector whose results join their calls by
// the command for a verified Substrate actor.
func commandJoinConnector(ctx context.Context, connectorName string) bool {
	if _, ok := substrateActorFrom(ctx); !ok {
		return false
	}
	switch normalizeConnectorNameForDigest(connectorName) {
	case "devin", "copilot":
		return true
	}
	return false
}

// commandJoinDigest is the command join key of req, "" when it has none.
// The arguments are compared as the canonical JSON of their value, so a
// harness that re-encodes them between the call and its result still joins.
func commandJoinDigest(ctx context.Context, req agentHookRequest) string {
	actor, ok := substrateActorFrom(ctx)
	if !ok || !commandJoinConnector(ctx, req.ConnectorName) ||
		strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.ToolName) == "" || req.ToolNameIsLabel ||
		req.ToolArgsAreHookEnvelope || req.ToolArgsProjectionUncertain {
		return ""
	}
	var args any
	if err := json.Unmarshal(req.ToolArgs, &args); err != nil || args == nil {
		return ""
	}
	if text, isText := args.(string); isText {
		// Copilot's toolArgs is a JSON document in a string.
		var inner any
		if err := json.Unmarshal([]byte(text), &inner); err == nil && inner != nil {
			args = inner
		}
	}
	canonical, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256([]byte("defenseclaw/substrate/tool-command-join/v1\x00" + actor.Atespace + "\x00" + actor.UID + "\x00" +
		normalizeConnectorNameForDigest(req.ConnectorName) + "\x00" + req.SessionID + "\x00" +
		strings.ToLower(strings.TrimSpace(req.ToolName)) + "\x00" + string(canonical)))
	return hex.EncodeToString(digest[:])
}

// prepareCommandJoinedSecretRead keeps a command-joined call's secret-read
// step 1 pending in the actor window and the session window. It reports
// false, so the chain starts at the proposal, when there is no join key, no
// actor window binding, or a window does not take it.
func (a *APIServer) prepareCommandJoinedSecretRead(ctx context.Context, req agentHookRequest,
	repository, rootRepository toolChainStore, rulesetFingerprint, inputFingerprint string,
	predecessor guardrail.ToolChainProjection,
) bool {
	digest := commandJoinDigest(ctx, req)
	start, ok := guardrail.ToolChainProjectionStep(predecessor, guardrail.ToolChainSecretReadThenEgress, 1)
	if digest == "" || !ok || rootRepository == nil {
		return false
	}
	in := audit.ToolChainPreparePendingInput{
		ConnectorInstanceID:  audit.ConnectorInstanceID(req.ConnectorInstanceID),
		ToolInvocationDigest: digest,
		PreSemanticEventID:   audit.SemanticEventID(req.SemanticEventID),
		PreInputFingerprint:  inputFingerprint,
		RulesetFingerprint:   rulesetFingerprint,
		Projection:           start,
	}
	for _, repo := range []toolChainStore{rootRepository, repository} {
		r, err := repo.PreparePending(ctx, in)
		if err != nil || r.Status != audit.ToolChainPendingPrepared && r.Status != audit.ToolChainPendingReplay {
			return false
		}
	}
	return true
}

// resolveCommandJoinedSecretRead lets a command-joined result decide its
// call's pending read: cleared when it proves nothing was read, promoted
// otherwise. A result that may show a credentials read whose call is not in
// the actor window is reported (the returned reason): the callout then
// refuses the actor's egress, as for a paired call (review rch3 R1).
func (a *APIServer) resolveCommandJoinedSecretRead(ctx context.Context, req agentHookRequest, profile connector.HookProfile,
	repository, rootRepository toolChainStore, inputFingerprint string, projection guardrail.ToolChainProjection,
) string {
	digest := commandJoinDigest(ctx, req)
	if digest == "" || rootRepository == nil {
		return ""
	}
	rulesetFingerprint, err := toolChainRulesetFingerprint(ctx, req.ConnectorName, profile)
	if err != nil {
		return "the active tool chain ruleset could not be fingerprinted: " + err.Error()
	}
	nothingRead := toolResultProvesNothingRead(req)
	in := audit.ToolChainResolvePendingInput{
		ConnectorInstanceID:      audit.ConnectorInstanceID(req.ConnectorInstanceID),
		ToolInvocationDigest:     digest,
		Outcome:                  audit.ToolChainPendingOutcomeFailure,
		RulesetFingerprint:       rulesetFingerprint,
		TerminalSemanticEventID:  audit.SemanticEventID(req.SemanticEventID),
		TerminalInputFingerprint: inputFingerprint,
		UnsuccessfulMayHaveRead:  !nothingRead,
		ResultMayHaveRead:        !nothingRead,
		ResultShowsRead:          !nothingRead && resultShowsRead(req),
	}
	root, rootErr := rootRepository.ResolvePending(ctx, in)
	if rootErr != nil {
		return "the leader did not take the step: " + rootErr.Error()
	}
	if repository != nil {
		_, _ = repository.ResolvePending(ctx, in)
	}
	if root.Status == audit.ToolChainPendingMissing && !nothingRead && resultMayBeAnUnjoinedRead(req, projection) {
		return "a tool result whose call is not in the actor's chain window (its call did not reach the leader)"
	}
	return ""
}

// noteUnclearedRead tells the leader, for a verified actor, that its
// credentials read started the chain uncleared, so the callout's refusal of
// the chain's egress says why (GAP-0338). A failure changes nothing: the
// read is in the window either way.
func (a *APIServer) noteUnclearedRead(ctx context.Context, connectorName string) {
	actor, ok := substrateActorFrom(ctx)
	st := a.substrateState()
	if !ok || st == nil || st.cfg.Chains == nil {
		return
	}
	_ = substrateNotes.deliver(ctx, substrateNote{client: st.cfg.Chains, actor: chainstate.Actor{Atespace: actor.Atespace, UID: actor.UID},
		why: unclearedReadWhy(connectorName), uncleared: true})
}

// substrateNote is an unrecorded step (or an uncleared read) of an actor for
// the leader.
type substrateNote struct {
	client    *chainstate.Client
	actor     chainstate.Actor
	why       string
	uncleared bool
	since     time.Time
}

func (n substrateNote) key() string {
	return n.actor.Atespace + "/" + n.actor.UID + "\x00" + strconv.FormatBool(n.uncleared)
}

func sendSubstrateNote(ctx context.Context, n substrateNote) error {
	if n.uncleared {
		return n.client.Uncleared(ctx, n.actor, n.why)
	}
	return n.client.Unrecorded(ctx, n.actor, n.why)
}

// substrateNoteQueue delivers the notes and keeps one that could not be
// delivered, retrying it in the background until the leader takes it or
// the chain window it is for has passed: a leader restart or a transient
// error must not leave the callout checking an incomplete window as if it
// were whole (GAP-0339 review F3). The newest note of an actor and kind
// replaces an older one; the queue is bounded, oldest out first.
type substrateNoteQueue struct {
	send    func(context.Context, substrateNote) error
	every   time.Duration
	keep    time.Duration
	timeout time.Duration

	mu      sync.Mutex
	pending map[string]substrateNote
	order   []string
	running bool
}

// maxPendingSubstrateNotes bounds the notes waiting for the leader.
const maxPendingSubstrateNotes = 4096

var substrateNotes = &substrateNoteQueue{send: sendSubstrateNote, every: 5 * time.Second,
	keep: 30 * time.Minute, timeout: substrateUnrecordedTimeout}

// deliver sends n once; on a failure it queues n for retry and returns the
// error.
func (q *substrateNoteQueue) deliver(ctx context.Context, n substrateNote) error {
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), q.timeout)
	err := q.send(uctx, n)
	cancel()
	if err == nil {
		return nil
	}
	if n.since.IsZero() {
		n.since = time.Now()
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending == nil {
		q.pending = map[string]substrateNote{}
	}
	if _, ok := q.pending[n.key()]; !ok {
		q.order = append(q.order, n.key())
	}
	q.pending[n.key()] = n
	for len(q.order) > maxPendingSubstrateNotes {
		delete(q.pending, q.order[0])
		q.order = q.order[1:]
	}
	if !q.running {
		q.running = true
		go q.retry()
	}
	return err
}

// retry resends the pending notes every q.every until none is left.
func (q *substrateNoteQueue) retry() {
	for {
		time.Sleep(q.every)
		q.mu.Lock()
		batch := make([]substrateNote, 0, len(q.order))
		for _, k := range q.order {
			batch = append(batch, q.pending[k])
		}
		q.mu.Unlock()
		for _, n := range batch {
			ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
			err := q.send(ctx, n)
			cancel()
			if err == nil || time.Since(n.since) > q.keep {
				if err != nil {
					fmt.Fprintf(os.Stderr, "[substrate] warning: %s/%s: gave up telling the leader of an unrecorded tool step after %s: %v\n",
						n.actor.Atespace, n.actor.UID, q.keep, err)
				}
				q.drop(n)
			}
		}
		q.mu.Lock()
		if len(q.order) == 0 {
			q.running = false
			q.mu.Unlock()
			return
		}
		q.mu.Unlock()
	}
}

// drop removes n unless a newer note of the same actor and kind replaced it.
func (q *substrateNoteQueue) drop(n substrateNote) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if cur, ok := q.pending[n.key()]; !ok || cur.why != n.why || !cur.since.Equal(n.since) {
		return
	}
	delete(q.pending, n.key())
	for i, k := range q.order {
		if k == n.key() {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
}

// pendingCount is the notes waiting for the leader.
func (q *substrateNoteQueue) pendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.order)
}

// readOnlyPrograms are the plain readers whose own error lines can prove a
// failed call read nothing (toolResultProvesNothingRead).
var readOnlyPrograms = map[string]struct{}{
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {}, "nl": {}, "tac": {}, "bat": {},
}

// readErrorPhrases end a reader's error line for an operand it did not read.
var readErrorPhrases = []string{
	"No such file or directory", "Permission denied", "Is a directory",
	"Not a directory", "No such device or address",
}

// maxProofResultBytes bounds the result text the proof reads.
const maxProofResultBytes = 64 << 10

// claudeCodeReadMissing begins the Read tool's error for a file that is not
// there.
const claudeCodeReadMissing = "File does not exist."

// toolResultProvesNothingRead reports an unsuccessful result that proves its
// call read no file (substrate-1 GAP-0337, GAP-0353). Its output lines
// (resultOutputLines: the output fields only, the harness's wrappers
// removed) must be one of:
//   - for one plain reader whose operands are all simple words (no operator,
//     redirect, pipe, quote, variable, glob or option): that reader's error
//     line for every operand ("cat: .env: No such file or directory") and an
//     exit status line. Such a call can print nothing but what it read, and a
//     file it printed would show as other lines;
//   - for that reader with its errors sent to /dev/null (cat .env
//     2>/dev/null): an exit status line that is not 0 and nothing else. Its
//     only channel printed nothing, and an empty file it read exits 0;
//   - for one simple word assigned to a variable and that reader on the
//     variable (F=.env; cat $F): as for the reader on the word;
//   - for Claude Code's Read tool: its "File does not exist." error.
//
// Anything else (no result text, other output, any other command shape)
// proves nothing: a failed call that printed a credentials file is a secret
// read.
func toolResultProvesNothingRead(req agentHookRequest) bool {
	lines, ok := resultOutputLines(req.Payload)
	if !ok || len(lines) == 0 {
		return false
	}
	if claudeCodeReadToolMissing(req, lines) {
		return true
	}
	command, ok := trustedBashCommandInput(actionfacts.Input{Tool: req.ToolName, Args: req.ToolArgs})
	if !ok {
		return false
	}
	program, operands, quiet, ok := plainReaderCall(command)
	if !ok {
		return false
	}
	exit := ""
	named := make(map[string]bool, len(operands))
	for _, line := range lines {
		if code, isExit := exitCodeOf(line); isExit {
			exit = code
			continue
		}
		operand, ok := readerErrorLine(program, line)
		if !ok || !slices.Contains(operands, operand) {
			return false
		}
		named[operand] = true
	}
	if quiet {
		return len(named) == 0 && exit != "" && exit != "0"
	}
	for _, operand := range operands {
		if !named[operand] {
			return false
		}
	}
	return true
}

// resultShowsRead reports a result whose own output shows its call may have
// read: any output line but a blank one, an exit status line, a reader's
// error line naming one of the command's operands, or the Read tool's
// missing-file error (GAP-0352, GAP-0353). A result too large to read shows
// one. It is the evidence a further result of a call needs to start the
// secret-read chain once an earlier result proved the read failed (the
// 1.0.10 lead's rule, STEER 7 and 8 2026-11-16): one that repeats the
// failure, carries no output or only the harness's metadata and wrappers
// shows none; one that printed shows one, so a no-read result never clears a
// read another result shows.
func resultShowsRead(req agentHookRequest) bool {
	lines, ok := resultOutputLines(req.Payload)
	if !ok {
		return true
	}
	if len(lines) == 0 || claudeCodeReadToolMissing(req, lines) {
		return false
	}
	program, operands := "", []string(nil)
	if command, ok := trustedBashCommandInput(actionfacts.Input{Tool: req.ToolName, Args: req.ToolArgs}); ok {
		if p, ops, _, plain := plainReaderCall(command); plain {
			program, operands = p, ops
		} else if words := strings.Fields(command); len(words) >= 2 {
			program, operands = words[0], words[1:]
		}
	}
	for _, line := range lines {
		if _, isExit := exitCodeOf(line); isExit {
			continue
		}
		if operand, ok := readerErrorLine(program, line); program != "" && ok && slices.Contains(operands, operand) {
			continue
		}
		return true
	}
	return false
}

// claudeCodeReadToolMissing is Claude Code's Read tool answering that its
// file does not exist: every output line is that error.
func claudeCodeReadToolMissing(req agentHookRequest, lines []string) bool {
	if req.ConnectorName != "claudecode" || req.ToolName != "Read" || len(lines) == 0 {
		return false
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, claudeCodeReadMissing) {
			return false
		}
	}
	return true
}

// assignedReaderRE is "F=word; reader $F" (or "&&", "$F" in double quotes,
// ${F}) with a word of no shell syntax.
var assignedReaderRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z0-9_./@%+,:-]+) *(?:;|&&) *([A-Za-z0-9_./-]+) (?:\$([A-Za-z_][A-Za-z0-9_]*)|"\$([A-Za-z_][A-Za-z0-9_]*)"|\$\{([A-Za-z_][A-Za-z0-9_]*)\})$`)

// plainReaderCall reads command as one plain reader on simple-word operands:
// its program (as typed), its operands, and whether its errors go to
// /dev/null (a trailing "2>/dev/null"). A variable assigned one simple word
// just before is read as that word.
func plainReaderCall(command string) (program string, operands []string, quiet, ok bool) {
	command = strings.TrimSpace(command)
	if rest, cut := strings.CutSuffix(command, " 2>/dev/null"); cut {
		command, quiet = strings.TrimSpace(rest), true
	}
	if m := assignedReaderRE.FindStringSubmatch(command); m != nil {
		name := m[4] + m[5] + m[6]
		if name != m[1] {
			return "", nil, false, false
		}
		command = m[3] + " " + m[2]
	}
	words := strings.Fields(command)
	if len(words) < 2 || strings.ContainsAny(command, "|&;<>()$`'\"\\*?[]{}!#=\n") {
		return "", nil, false, false
	}
	if _, reader := readOnlyPrograms[path.Base(words[0])]; !reader {
		return "", nil, false, false
	}
	for _, operand := range words[1:] {
		if strings.HasPrefix(operand, "-") {
			return "", nil, false, false
		}
	}
	return words[0], words[1:], quiet, true
}

// exitCodeOf is the code of the exit status line a connector adds to a
// failed shell result ("Exit code 1").
func exitCodeOf(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "Exit code ")
	if !ok {
		return "", false
	}
	if _, err := strconv.Atoi(rest); err != nil {
		return "", false
	}
	return rest, true
}

// readerErrorLine is the operand of program's error line "program: operand:
// phrase". The program prefix may be absent, typed as a path (/bin/cat), or
// the reader's own name; the operand may be in one pair of quotes, as GNU
// coreutils quotes one that needs it ('.env' or "it's").
func readerErrorLine(program, line string) (string, bool) {
	if program != "" {
		base := path.Base(program)
		if i := strings.Index(line, ": "); i > 0 {
			if prefix := line[:i]; prefix == program || prefix == base || strings.HasSuffix(prefix, "/"+base) {
				line = line[i+2:]
			}
		}
	}
	for _, phrase := range readErrorPhrases {
		operand, ok := strings.CutSuffix(line, ": "+phrase)
		if !ok || operand == "" {
			continue
		}
		if n := len(operand); n >= 2 && (operand[0] == '\'' && operand[n-1] == '\'' || operand[0] == '"' && operand[n-1] == '"') {
			operand = operand[1 : n-1]
		}
		return operand, operand != ""
	}
	return "", false
}

// resultTextKeys are the payload keys where a connector's harness puts a
// tool's output and error text (Claude Code tool_response and error, Cursor
// error_message and tool_output, Hermes extra.result, OpenCode, Amp and
// Codex tool_response, Antigravity output and error).
var resultTextKeys = []string{
	"tool_response", "toolResponse", "tool_output", "toolOutput", "tool_result", "toolResult",
	"output", "result", "response", "stdout", "stderr",
	"error", "error_message", "errorMessage", "error_details", "errorDetails",
}

// resultMetadataKeys are fields inside a result that a harness fills with
// its own description of the call, never with what the call printed: Claude
// Code's Bash result (interrupted, isImage, noOutputExpected,
// returnCodeInterpretation, persistedOutputPath, backgroundTaskId, sandbox
// fields) and the failure flags. An unknown field is read as output.
var resultMetadataKeys = map[string]struct{}{
	"interrupted": {}, "isimage": {}, "nooutputexpected": {}, "returncodeinterpretation": {},
	"persistedoutputpath": {}, "persistedoutputsize": {}, "backgroundtaskid": {}, "is_error": {},
	"is_interrupt": {}, "duration_ms": {}, "sandboxed": {}, "dangerouslydisablesandbox": {},
}

// resultOutputLines are the output lines of a result payload, as the proof
// and resultShowsRead read them: every string under its result keys (and the
// same keys under extra), a string that holds a JSON object or array read as
// that value, but status, type, kind and id fields and the harness's
// metadata fields (resultMetadataKeys); each line trimmed, with Claude
// Code's wrappers removed (a <tool_use_error> tag, an "Error: " before the
// exit status line, the "Shell cwd was reset to ..." trailer) and blank
// lines dropped. ok is false when the result is larger than
// maxProofResultBytes. The payload is the harness plugin's, not the model's.
func resultOutputLines(payload map[string]any) (lines []string, ok bool) {
	var text []string
	size := 0
	for _, scope := range []map[string]any{payload, nestedResultScope(payload)} {
		for _, key := range resultTextKeys {
			if value, has := scope[key]; has && !collectText(value, &text, &size) {
				return nil, false
			}
		}
	}
	for _, chunk := range text {
		for _, line := range strings.Split(chunk, "\n") {
			if line = normalizeResultLine(line); line != "" {
				lines = append(lines, line)
			}
		}
	}
	return lines, true
}

func normalizeResultLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimSpace(strings.TrimPrefix(line, "<tool_use_error>"))
	line = strings.TrimSpace(strings.TrimSuffix(line, "</tool_use_error>"))
	if rest, ok := strings.CutPrefix(line, "Error: "); ok {
		if _, isExit := exitCodeOf(rest); isExit || strings.HasPrefix(rest, claudeCodeReadMissing) {
			line = rest
		}
	}
	if strings.HasPrefix(line, "Shell cwd was reset to ") {
		return ""
	}
	return line
}

func nestedResultScope(payload map[string]any) map[string]any {
	extra, _ := payload["extra"].(map[string]any)
	return extra
}

func collectText(value any, out *[]string, size *int) bool {
	switch v := value.(type) {
	case string:
		*size += len(v)
		if *size > maxProofResultBytes {
			return false
		}
		if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var decoded any
			if json.Unmarshal([]byte(trimmed), &decoded) == nil {
				return collectText(decoded, out, size)
			}
		}
		*out = append(*out, v)
	case map[string]any:
		for key, item := range v {
			if resultEnumKey(key) {
				continue
			}
			if _, meta := resultMetadataKeys[strings.ToLower(key)]; meta {
				continue
			}
			if !collectText(item, out, size) {
				return false
			}
		}
	case []any:
		for _, item := range v {
			if !collectText(item, out, size) {
				return false
			}
		}
	}
	return true
}

// resultEnumKey is a field inside a result whose value is a label, not
// output (opencode_v2_status, a content block type, an id).
func resultEnumKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "status") || lower == "type" || lower == "resulttype" || lower == "kind" ||
		lower == "id" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(key, "Id") || strings.HasSuffix(key, "ID")
}
