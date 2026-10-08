// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/google/uuid"
)

func (a *APIServer) handleACPCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.writeJSON(w, http.StatusOK, acp.BuiltinCatalog())
}

func (a *APIServer) handleACPProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "configuration unavailable"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": cfg.ACP.Enabled, "mode": effectiveACPMode(cfg.ACP, ""),
		"default_profile": cfg.ACP.DefaultProfile, "profiles": cfg.ACP.Profiles,
	})
}

func (a *APIServer) handleACPChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serverNonce, err := acp.NewHTTPAuthNonce()
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ACP challenge unavailable"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"server_nonce": serverNonce})
}

func (a *APIServer) handleACPEvaluate(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, acp.MaxTurnEvaluationBytes+(64<<10))
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req acp.Evaluation
	if err := decoder.Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ACP evaluation body"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ACP evaluation body"})
		return
	}
	maxPayload := acp.MaxFrameBytes
	if req.Aggregate {
		maxPayload = acp.MaxTurnEvaluationBytes
	}
	if len(req.Payload) == 0 || len(req.Payload) > maxPayload {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP payload is empty or too large"})
		return
	}
	if req.Aggregate {
		if req.Direction != acp.AgentToClient || req.Surface != acp.SurfaceOutput || req.Method != "session/update" ||
			acp.ValidateTurnEvaluationPayload(req.Payload) != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP completed-turn metadata does not match payload"})
			return
		}
	} else {
		// A guard forwards a null-id error response (GAP-0351); Secure
		// Client keeps the parser of main.
		parse := acp.ParseMessageAllowingNullIDErrors
		if a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration() {
			parse = acp.ParseMessage
		}
		msg, err := parse(req.Payload)
		if err != nil || msg.Method != req.Method || acp.Classify(msg, req.Direction) != req.Surface {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP envelope metadata does not match payload"})
			return
		}
	}
	agent, err := acp.LookupAgent(req.AgentID)
	if err != nil || strings.TrimSpace(agent.ConnectorID) == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown or unbound ACP agent"})
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil || !cfg.ACP.Enabled {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ACP guard is not enabled"})
		return
	}
	profileName, profile, ok, matched := resolveACPProfileForPair(cfg.ACP, req.ClientID, req.AgentID, req.Profile)
	if !matched {
		// Distinguishable on purpose: a stale guard argv and an undefined
		// profile need different fixes, and "not configured" sent operators
		// looking for a missing profiles: entry that was present all along.
		a.writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "ACP profile does not match the configured binding for this client and agent; re-run acp setup",
		})
		return
	}
	if !ok {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP profile is not configured"})
		return
	}
	if !acpPairIsBound(cfg.ACP, req.ClientID, req.AgentID, profileName) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP client or agent binding is disabled or pinned to another profile"})
		return
	}
	if !acpBindingAllowed(profile.AllowedClients, req.ClientID) || !acpBindingAllowed(profile.AllowedAgents, req.AgentID) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP client or agent is outside the selected profile"})
		return
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		credential, ok := acpEnterpriseCredentialFromContext(r.Context())
		if !ok || credential.ClientID != req.ClientID || credential.AgentID != req.AgentID || credential.Profile != profileName {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP enterprise credential is outside its enrolled binding"})
			return
		}
	}
	mode := effectiveACPMode(cfg.ACP, profileName)
	if string(req.Mode) != mode {
		a.writeJSON(w, http.StatusConflict, map[string]string{
			"error": "ACP runtime mode does not match central policy; re-run managed setup",
		})
		return
	}
	ctx := acpEvaluationContext(r.Context(), req, agent.ConnectorID)
	// Resolve the identity-based guardrail profile once, with the ACP
	// agent's connector, as the hook, proxy and inspect paths do: resolved
	// lazily, the request had no connector, so a connectors assignment never
	// selected ACP traffic (GAP-0311).
	ctx = a.withGuardrailProfileDecision(ctx, agent.ConnectorID)
	if slices.Contains(profile.DeniedMethods, req.Method) {
		verdict := acp.Verdict{Action: "block", RawAction: "block", Severity: "HIGH", Reason: "method denied by ACP profile"}
		if mode != string(acp.ModeAction) {
			verdict.Action, verdict.WouldBlock = "allow", true
		}
		a.traceACPDecisionV8(ctx, agent.ConnectorID, req, &ToolInspectVerdict{
			Action: verdict.Action, RawAction: verdict.RawAction, Severity: verdict.Severity,
			Reason: verdict.Reason, Mode: mode, WouldBlock: verdict.WouldBlock,
		}, started, func(traceCtx context.Context) hookEvaluationContext {
			a.recordACPEvaluationV8(traceCtx, req, verdict, nil, nil, agent.ConnectorID, profileName, time.Since(started))
			return hookEvaluationContext{}
		})
		a.writeJSON(w, http.StatusOK, verdict)
		return
	}

	direction := string(req.Surface)
	if req.Surface == acp.SurfaceOutput {
		direction = "completion"
	}
	if req.Surface == acp.SurfacePrompt {
		direction = "prompt"
	}
	scanCtx, cancel := context.WithTimeout(ctx, inspectScanTimeout)
	defer cancel()
	// Scan the frame's strings, not the marshalled envelope. Content rules
	// anchor on prose boundaries, and inside raw JSON every value is preceded
	// by a quote, so envelope scanning makes detection depend on whether a
	// rule's boundary alternation happens to admit `"`. See InspectableText.
	content := acp.InspectableText(req.Payload)
	if content == "" {
		content = string(req.Payload)
	}
	verdict := a.inspectMessageContent(scanCtx, &ToolInspectRequest{
		Tool: "message", Content: content, Direction: direction,
		Connector: agent.ConnectorID, contentScope: ruleContentScopeUntrusted,
	})
	if verdict == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ACP inspection unavailable"})
		return
	}
	verdict.applyMode(mode)
	result := acp.Verdict{
		Action: verdict.Action, RawAction: verdict.RawAction, Severity: verdict.Severity,
		Reason: verdict.Reason, WouldBlock: verdict.WouldBlock,
	}
	record := func(recordCtx context.Context) hookEvaluationContext {
		var evaluation hookEvaluationContext
		if len(verdict.DetailedFindings) > 0 {
			// A rule match is a finding of the agent's connector, as it is
			// on the hook path: a blocked ACP prompt raised no alert
			// (GAP-1302).
			evaluation = a.emitInspectVerdictFindings(recordCtx, "inspect-http",
				hookEvaluationTarget(agent.ConnectorID, "acp"), acpTraceTargetType(req), verdict,
				time.Since(started), "emit_acp_findings")
		}
		ruleIDs := scanner.TopRuleIDs(ruleFindingsToInspect(verdict.DetailedFindings, ""), 8)
		a.recordACPEvaluationV8(recordCtx, req, result, verdict.Findings, ruleIDs,
			agent.ConnectorID, profileName, time.Since(started))
		return evaluation
	}
	if len(verdict.DetailedFindings) > 0 {
		// The hook path records a decision as a span; ACP wrote only the log
		// row, so Tempo and a Galileo-only deployment never saw an ACP block
		// (GAP-1836).
		a.traceACPDecisionV8(ctx, agent.ConnectorID, req, verdict, started, record)
	} else {
		record(ctx)
	}
	// The audit row keeps the source reason; the editor gets the wording the
	// hook connectors show ("DefenseClaw policy blocked this action (rule
	// SEC-AWS-KEY: AWS access key). Do not retry it in another form."), not
	// the raw "matched: ID:title" text (GAP-1793), through the same sink
	// barrier as the inspect response.
	result.Reason = verdict.sanitizeForResponse(false).Reason
	if req.Direction == acp.AgentToClient && req.Surface == acp.SurfaceOutput {
		result.Reason = acpWithheldOutputReason(result.Reason)
	}
	a.writeJSON(w, http.StatusOK, result)
}

// acpWithheldOutputReason words a block of the agent's own output
// (session/update). The guard can only withhold what the agent sent: a tool
// the agent runs itself has already run when its tool_call update arrives,
// so "blocked this action ... Do not retry it" told the user nothing had
// happened while the file was already written (GAP-1956). Other reasons
// (evaluation unavailable, a configured message) are kept.
func acpWithheldOutputReason(reason string) string {
	for _, prefix := range []string{
		"DefenseClaw policy blocked this action (",
		"DefenseClaw blocked this action under your organization's policy (",
	} {
		rest, ok := strings.CutPrefix(reason, prefix)
		if !ok {
			continue
		}
		subject, _, ok := strings.Cut(rest, "). "+agentBlockNoRetry)
		if !ok || subject == "" {
			break
		}
		policy := "DefenseClaw policy withheld agent output ("
		if strings.Contains(prefix, "organization") {
			policy = "DefenseClaw withheld agent output under your organization's policy ("
		}
		return policy + subject + "). The agent may already have run the step; check its effects."
	}
	return reason
}

// acpEvaluationContext attributes an ACP evaluation the way the hook path
// attributes a hook call: to the ACP session the frame belongs to and, on a
// per-user gateway (which runs as its user and is the only holder of the
// user's ACP token), to that user. The guard sends no identity headers, so
// ACP finding, scan and span rows named no user or session and could not be
// joined to the hook rows of the same session (GAP-1946).
type acpUnboundAgentContextKey struct{}

func acpEvaluationContext(ctx context.Context, req acp.Evaluation, connector string) context.Context {
	env := audit.EnvelopeFromContext(ctx)
	changed := false
	if env.Connector != connector {
		env.Connector, changed = connector, true
	}
	if session := acpFrameSessionID(req); session != "" {
		if SessionIDFromContext(ctx) == "" {
			ctx = ContextWithSessionID(ctx, session)
		}
		if env.SessionID == "" {
			env.SessionID, changed = session, true
		}
	}
	if changed {
		ctx = audit.ContextWithEnvelope(ctx, env)
	}
	identity := AgentIdentityFromContext(ctx)
	updated := false
	if identity.UserID == "" && identity.UserName == "" && !gatewayRunsAsServiceAccount() {
		if user := useridentity.Current(); !user.Empty() {
			identity.UserID, identity.UserIDKind, identity.UserName = user.ID, user.IDKind, user.Name
			updated = true
		}
	}
	// The agent an ACP client drives is the connector's install, so its
	// records carry the agent identity the hook path derives for it.
	var facts agentIdentityFacts
	if identity.IdentityID == "" {
		if facts = resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connector}); facts.ID != "" {
			identity.IdentityID, identity.IdentityVerified = facts.ID, facts.Verified
			updated = true
		}
	}
	// An unbound managed credential must not adopt a hook agent merely
	// because its caller supplied the same session ID.
	if identity.IdentityID == "" && !ManagedEnterpriseActive() {
		ctx = context.WithValue(ctx, acpUnboundAgentContextKey{}, true)
	}
	newSession := false
	// And the instance (ais-) of the ACP session the frame belongs to,
	// derived from that identity as the hook path derives one per session; a
	// frame that names no session has none (GAP-0252). Secure Client ACP
	// records carry no instance, as on main (issue #1092).
	if session := SessionIDFromContext(ctx); identity.AgentInstanceID == "" && identity.IdentityID != "" && session != "" && !ManagedEnterpriseActive() {
		if registry := SharedAgentRegistry(); registry != nil {
			resolved, minted := registry.ResolveForAgentIdentity(ctx, identity.IdentityID, session, "")
			newSession = minted
			if resolved.AgentInstanceID != "" {
				identity.AgentInstanceID = resolved.AgentInstanceID
				updated = true
			}
		}
	}
	// Recorded for `defenseclaw agent identities` as the hook path and the
	// LLM proxy record theirs, so an agent used only through ACP is listed
	// and its ACP sessions are counted (GAP-0315).
	sharedAgentIdentities.observe(facts, SessionIDFromContext(ctx), newSession)
	if updated {
		ctx = ContextWithAgentIdentity(ctx, identity)
	}
	return ctx
}

// acpFrameSessionID is the ACP sessionId a single frame names, or "".
func acpFrameSessionID(req acp.Evaluation) string {
	payload := req.Payload
	if req.Aggregate {
		var turn struct {
			Frames []json.RawMessage `json:"frames"`
		}
		if json.Unmarshal(payload, &turn) != nil || len(turn.Frames) == 0 {
			return ""
		}
		payload = turn.Frames[0]
	}
	msg, err := acp.ParseMessage(payload)
	if err != nil || len(msg.Params) == 0 {
		return ""
	}
	var params struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(msg.Params, &params) != nil || !hookModelV8Identifier(params.SessionID) {
		return ""
	}
	return params.SessionID
}

// acpDecisionTraceRuntime starts the spans of one ACP decision.
type acpDecisionTraceRuntime interface {
	StartAgentTrace(context.Context, observability.SpanAgentInvokeInput) (context.Context, *observabilityruntime.AgentTrace, error)
	inspectTraceV8Runtime
}

const acpTraceV8Producer = "gateway.acp.trace"

// traceACPDecisionV8 records one ACP decision as an "invoke_agent <agent>"
// span with its apply_guardrail child, and runs record (the finding and
// verdict rows) inside the child so those rows carry its trace and span IDs.
// The agent span is what Galileo ingests: it has no guardrail span shape, so
// an ACP block that was only an apply_guardrail span reached Tempo but never
// Galileo (GAP-1836).
func (a *APIServer) traceACPDecisionV8(
	ctx context.Context, connector string, req acp.Evaluation, verdict *ToolInspectVerdict,
	started time.Time, record func(context.Context) hookEvaluationContext,
) {
	runtime, ok := a.observabilityV8RuntimeEmitter().(acpDecisionTraceRuntime)
	if !ok || runtime == nil || verdict == nil {
		record(ctx)
		return
	}
	targetType := acpTraceTargetType(req)
	agentInput := acpAgentInvokeInputV8(ctx, connector, verdict, started)
	agentCtx, agentSpan, err := runtime.StartAgentTrace(ctx, agentInput)
	if err != nil || agentCtx == nil {
		agentCtx, agentSpan = ctx, nil
	}
	if agentSpan != nil {
		defer agentSpan.Abort()
	}
	guardCtx, guardSpan, err := runtime.StartGuardrailApplyTrace(agentCtx, observability.SpanGuardrailApplyInput{
		Kind: "INTERNAL", StartTimeUnixNano: uint64(started.UnixNano()),
		DefenseClawGuardrailName: "inspect", DefenseClawGuardrailTargetType: targetType,
	})
	if err != nil || guardCtx == nil {
		guardCtx, guardSpan = agentCtx, nil
	}
	if guardSpan != nil {
		defer guardSpan.Abort()
	}
	evaluation := record(guardCtx)
	if guardSpan != nil {
		if input, ok := a.guardrailApplyTraceV8Input(guardCtx, connector, "", targetType, verdict,
			time.Since(started), evaluation); ok {
			input.StartTimeUnixNano = uint64(started.UnixNano())
			_ = guardSpan.End(input)
		}
	}
	if agentSpan != nil {
		ruleIDs := evaluation.RuleIDs
		if len(ruleIDs) == 0 {
			ruleIDs = scanner.TopRuleIDs(ruleFindingsToInspect(verdict.DetailedFindings, ""), 8)
		}
		if outcome, ok := hookGuardrailOutcomeFor(verdict.Action, verdict.Severity, verdict.Reason, ruleIDs); ok {
			agentInput.DefenseClawGuardrailAction, agentInput.DefenseClawGuardrailRuleID,
				agentInput.DefenseClawGuardrailSeverity = guardrailOutcomeAttributes(outcome)
		}
		agentInput.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
		_ = agentSpan.End(agentInput)
	}
}

// acpAgentInvokeInputV8 is the agent root of one ACP decision: the agent the
// editor drives, its ACP session and the user.
func acpAgentInvokeInputV8(
	ctx context.Context, connector string, verdict *ToolInspectVerdict, started time.Time,
) observability.SpanAgentInvokeInput {
	connector = hookDecisionMetricConnector(connector)
	connectorKnown := connector != "unknown"
	if !connectorKnown {
		connector = ""
	}
	session := audit.EnvelopeFromContext(ctx).SessionID
	outcome := observability.OutcomeCompleted
	if strings.EqualFold(strings.TrimSpace(verdict.Action), "block") {
		outcome = observability.OutcomeBlocked
	}
	input := observability.SpanAgentInvokeInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway, Connector: connector, Action: "invoke_agent", Phase: "finalize",
			Correlation: gatewayGeneratedCorrelation(ctx, connector),
			Provenance:  observability.FamilyProvenanceInput{Producer: acpTraceV8Producer},
		},
		Outcome: outcome, Kind: "INTERNAL",
		StartTimeUnixNano:                  uint64(started.UnixNano()),
		EndTimeUnixNano:                    uint64(time.Now().UTC().UnixNano()),
		Status:                             observability.NewTraceStatusOK(),
		DefenseClawAgentType:               firstNonEmpty(connector, "acp"),
		DefenseClawTelemetryInputReported:  false,
		DefenseClawContentInputState:       "not_reported",
		DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState:      "not_reported",
		GenAIOperationName:                 observability.Present("invoke_agent"),
		DefenseClawConnectorSource:         hookV8OptionalIdentifier(connector),
		GenAIAgentName:                     hookV8OptionalIdentifier(connector),
		GenAIConversationID:                hookV8OptionalIdentifier(session),
		DefenseClawSessionRootID:           hookV8OptionalIdentifier(session),
		ConditionConnectorKnown:            connectorKnown,
		ConditionOperationTerminal:         true,
	}
	caller := auditCallerIdentity(ctx)
	input.UserID = hookV8OptionalIdentifier(caller.ID)
	input.DefenseClawUserIDKind = v8UserIDKind(caller.IDKind)
	input.DefenseClawUserName = hookV8OptionalIdentifier(caller.Name)
	input.DefenseClawAgentIdentityID = agentIdentityV8(agentIdentityIDForTraffic(ctx, AgentIdentityFromContext(ctx)))
	caller.Identity.applyTo(&input)
	return input
}

// acpTraceTargetType is the guardrail target of an ACP frame: what the
// editor sends is a prompt, what the agent sends is a completion.
func acpTraceTargetType(req acp.Evaluation) string {
	if req.Direction == acp.AgentToClient {
		return "completion"
	}
	return "prompt"
}

// findings is carried separately from verdict because acp.Verdict is the wire
// type sent back to the guard, which needs only the decision. Telemetry does
// need them: DefenseClawGuardrailRuleIds and
// DefenseClawGuardrailFindingCount are both derived from
// guardrailEventRequest.Findings, so omitting them published every ACP
// evaluation as rule_ids absent / finding_count 0 while the reason named the
// rule that matched -- a SIEM rolling up either attribute saw no ACP findings
// at all, and the hook lane reported them for identical content.
//
// ruleIDs are the matched rules' own IDs, as the hook rows and the
// apply_guardrail span name them. Without them the IDs were re-derived from
// the finding strings, which turns a rule-pack rule into
// "UNKNOWN-<rule id>" (GAP-1946).
func (a *APIServer) recordACPEvaluationV8(
	ctx context.Context, req acp.Evaluation, verdict acp.Verdict, findings, ruleIDs []string,
	connector, profile string, elapsed time.Duration,
) {
	action := strings.ToLower(strings.TrimSpace(verdict.Action))
	if action == "confirm" {
		action = "block"
	}
	if action != "allow" && action != "alert" && action != "block" {
		action = "allow"
	}
	direction := "prompt"
	if req.Direction == acp.AgentToClient {
		direction = "completion"
	}
	severity := strings.ToUpper(strings.TrimSpace(verdict.Severity))
	if severity == "" {
		severity = "NONE"
	}
	facts, err := newAPIGuardrailEventV8Facts(ctx, connector, guardrailEventRequest{
		EvaluationID: uuid.NewString(), Direction: direction, Action: action,
		RawAction: verdict.RawAction, WouldBlock: verdict.WouldBlock, Severity: severity,
		Reason: verdict.Reason, Findings: findings,
		ElapsedMs: float64(elapsed) / float64(time.Millisecond),
	})
	if err != nil {
		return
	}
	if len(ruleIDs) > 0 {
		facts.ruleIDs = inspectTraceV8RuleIDs(ruleIDs)
	}
	facts.acp = &acpEvaluationV8Context{
		client: req.ClientID, agent: req.AgentID, method: req.Method,
		direction: string(req.Direction), surface: string(req.Surface), profile: profile,
	}
	_ = a.emitGuardrailEventV8(ctx, facts)
}

// resolveACPProfileForPair resolves the profile governing one client/agent
// pair and refuses a guard that asks for a different one.
//
// The guard carries its profile in argv, pinned into its contract lock at
// setup, so a request naming a profile the configuration does not assign to
// that pair is stale or forged and must not be evaluated under either name.
func resolveACPProfileForPair(
	cfg config.ACPConfig, client, agent, requested string,
) (name string, profile config.ACPProfile, defined bool, matched bool) {
	resolved := cfg.ACPProfileForPair(client, agent)
	if resolved == "" {
		resolved = "default"
	}
	if requested = strings.TrimSpace(requested); requested != "" && requested != resolved {
		return "", config.ACPProfile{}, false, false
	}
	profile, defined = cfg.Profiles[resolved]
	return resolved, profile, defined, true
}

// acpPairIsBound reports whether both halves of a pair are enabled and agree
// with the resolved profile.
//
// A per-pair binding is the authority when present: it exists precisely so one
// pair can use a profile the client or agent pin does not name, so requiring
// the pins to match it would defeat it. The pins still have to admit the pair
// at all, so disabling a client or an agent continues to disable every pair
// that uses it.
func acpPairIsBound(cfg config.ACPConfig, client, agent, profileName string) bool {
	return len(cfg.ACPPairBindingRefusals(client, agent, profileName)) == 0
}

func effectiveACPMode(cfg config.ACPConfig, profileName string) string {
	if profileName != "" {
		if profile, ok := cfg.Profiles[profileName]; ok && (profile.Mode == "observe" || profile.Mode == "action") {
			return profile.Mode
		}
	}
	if cfg.Mode == "action" {
		return "action"
	}
	return "observe"
}

func resolveACPProfile(cfg config.ACPConfig, requested string) (string, config.ACPProfile, bool) {
	name := strings.TrimSpace(requested)
	if name == "" {
		name = strings.TrimSpace(cfg.DefaultProfile)
	}
	if name == "" {
		name = "default"
	}
	profile, ok := cfg.Profiles[name]
	return name, profile, ok
}

func acpBindingAllowed(allow []string, value string) bool {
	return len(allow) == 0 || slices.Contains(allow, value)
}

func isACPAPIPath(path string) bool {
	return path == "/api/v1/acp/challenge" || path == "/api/v1/acp/evaluate" || strings.HasPrefix(path, "/v1/acp/")
}

type acpEnterpriseCredentialContextKey struct{}

func withACPEnterpriseCredential(ctx context.Context, credential acp.EnterpriseCredential) context.Context {
	return context.WithValue(ctx, acpEnterpriseCredentialContextKey{}, credential)
}

func acpEnterpriseCredentialFromContext(ctx context.Context) (acp.EnterpriseCredential, bool) {
	credential, ok := ctx.Value(acpEnterpriseCredentialContextKey{}).(acp.EnterpriseCredential)
	return credential, ok
}

// attachACPSubject names the account behind an authenticated ACP request.
// A managed request carries the credential `enterprise acp enroll` issued
// for one principal (uid:N or sid:S-...): the gateway keeps the record in
// its protected state and only the bearer copy is in that user's private
// ACP runtime, so presenting it proves the account as a per-user hook
// credential does (GAP-0200, GAP-0206). A home: principal names no account
// and binds none: the user the caller claimed is dropped too, so its records
// name no one. A per-user gateway's caller is its own account. Under the
// Secure Client integration identity facts are off and nothing changes.
func (a *APIServer) attachACPSubject(ctx context.Context) context.Context {
	ctx = PromoteSessionIfAuthenticated(ctx)
	credential, enrolled := acpEnterpriseCredentialFromContext(ctx)
	if !enrolled {
		return a.attachProcessOwnerSubject(ctx)
	}
	if !identityFactsEnabled.Load() {
		return ctx
	}
	identity := acpPrincipalIdentity(credential.Principal)
	if identity == "" {
		claimed := AgentIdentityFromContext(ctx)
		claimed.UserID, claimed.UserIDKind, claimed.UserName = "", "", ""
		return ContextWithAgentIdentity(ctx, claimed)
	}
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	return attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), identity,
		sanitizeLLMEventUser(userScopedIdentityName(identity)), subjectSourceUserCredential)
}

// acpPrincipalIdentity is the canonical account of an enrollment principal
// in this platform's kind: a uid (uid:1001) on Linux and macOS, a SID
// (sid:S-1-5-21-...) on Windows. Those are the accounts enrollment proves
// own the home the bearer is published to. Any other principal, such as the
// home-directory fallback or the other platform's kind, names no account
// and gives "".
func acpPrincipalIdentity(principal string) string {
	kind, value, _ := strings.Cut(strings.TrimSpace(principal), ":")
	identity, ok := connector.CanonicalUserScopedIdentity(value)
	if !ok {
		return ""
	}
	want, wantKind := "uid", useridentity.KindPOSIXUID
	if runtime.GOOS == "windows" {
		want, wantKind = "sid", useridentity.KindWindowsSID
	}
	if kind != want || useridentity.KindForID(identity) != wantKind {
		return ""
	}
	return identity
}

// authenticateACPToken applies different custody models without widening the
// bearer onto any non-ACP route. Unmanaged mode uses the single local sidecar;
// managed enterprise mode requires one administrator-owned, per-principal and
// per-binding credential record and carries its scope into evaluation.
func (a *APIServer) authenticateACPToken(r *http.Request, candidate string) (*http.Request, bool) {
	if a == nil || a.scannerCfg == nil || r == nil {
		return r, false
	}
	if !managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		return r, a.acpAPITokenMatches(candidate)
	}
	credential, ok := acp.MatchEnterpriseCredential(a.scannerCfg.DataDir, candidate)
	if !ok {
		return r, false
	}
	return r.WithContext(withACPEnterpriseCredential(r.Context(), credential)), true
}

func (a *APIServer) authenticateACPSignedRequest(r *http.Request) (*http.Request, string, string, bool) {
	if a == nil || a.scannerCfg == nil || r == nil || r.Method != http.MethodPost ||
		(r.URL.Path != "/api/v1/acp/challenge" && r.URL.Path != "/api/v1/acp/evaluate") {
		return r, "", "", false
	}
	keyID := strings.TrimSpace(r.Header.Get(acp.AuthKeyIDHeader))
	nonce := strings.TrimSpace(r.Header.Get(acp.AuthNonceHeader))
	candidateMAC := strings.TrimSpace(r.Header.Get(acp.AuthRequestMACHeader))
	if len(keyID) != 64 || len(nonce) != 64 || len(candidateMAC) != 64 {
		return r, "", "", false
	}
	var token string
	if managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		credential, secret, ok := acp.MatchEnterpriseCredentialKeyID(a.scannerCfg.DataDir, keyID)
		if !ok {
			return r, "", "", false
		}
		token = secret
		r = r.WithContext(withACPEnterpriseCredential(r.Context(), credential))
	} else {
		var ok bool
		token, ok = a.loadACPAPIToken()
		if !ok || !constantTimeStringMatch(acp.HTTPAuthKeyID(token), keyID) {
			return r, "", "", false
		}
	}
	maxBody := int64(1)
	if r.URL.Path == "/api/v1/acp/evaluate" {
		maxBody = int64(acp.MaxTurnEvaluationBytes + (64 << 10) + 16)
	}
	limited := io.LimitReader(r.Body, maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil || int64(len(body)) > maxBody {
		return r, "", "", false
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !acp.VerifyHTTPRequestMAC(token, keyID, nonce, r.Method, r.URL.Path, body, candidateMAC) {
		return r, "", "", false
	}
	if r.URL.Path == "/api/v1/acp/challenge" {
		if len(body) != 0 {
			return r, "", "", false
		}
		// The challenge is a bodiless POST, so defenseclaw-acp sends it with
		// no Content-Type -- but it still traverses apiCSRFProtect on the way
		// to the handler, which rejects any non-JSON mutation with 415. Declare
		// JSON here, after the request MAC is verified, for the same reason the
		// evaluation branch below does: a browser cannot forge a signed ACP
		// request, so the CSRF gate has nothing left to protect on this route.
		r.Header.Set("Content-Type", "application/json")
	} else {
		challengeNonce := strings.TrimSpace(r.Header.Get(acp.AuthChallengeNonceHeader))
		serverNonce := strings.TrimSpace(r.Header.Get(acp.AuthServerNonceHeader))
		plaintext, decryptErr := acp.OpenHTTPPayload(
			token, keyID, challengeNonce, serverNonce, nonce, r.Method, r.URL.Path, body,
		)
		if decryptErr != nil || len(plaintext) > acp.MaxTurnEvaluationBytes+(64<<10) {
			return r, "", "", false
		}
		r.Body = io.NopCloser(bytes.NewReader(plaintext))
		r.ContentLength = int64(len(plaintext))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set(acp.AuthKeyIDHeader, keyID)
	r.Header.Set(acp.AuthNonceHeader, nonce)
	return r, token, nonce, true
}

type acpSignedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *acpSignedResponse) Header() http.Header { return w.header }

func (w *acpSignedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *acpSignedResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.body.Len()+len(body) > 64<<10 {
		return 0, errors.New("ACP signed response exceeds its size bound")
	}
	return w.body.Write(body)
}

func serveACPSignedResponse(w http.ResponseWriter, r *http.Request, next http.Handler, token, nonce string) {
	capture := &acpSignedResponse{header: w.Header().Clone()}
	next.ServeHTTP(capture, r)
	if capture.status == 0 {
		capture.status = http.StatusOK
	}
	keyID := r.Header.Get(acp.AuthKeyIDHeader)
	capture.header.Set(acp.AuthResponseMACHeader, acp.HTTPResponseMAC(token, keyID, nonce, capture.status, capture.body.Bytes()))
	for name := range w.Header() {
		w.Header().Del(name)
	}
	for name, values := range capture.header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(capture.status)
	_, _ = w.Write(capture.body.Bytes())
}

// acpAPITokenMatches authenticates the guard with a credential that has no
// authority outside ACP routes. The token stays in a mode-0600 sidecar rather
// than IDE JSON or config.yaml.
func (a *APIServer) acpAPITokenMatches(candidate string) bool {
	if a == nil || a.scannerCfg == nil || candidate == "" {
		return false
	}
	expected, ok := a.loadACPAPIToken()
	return ok && constantTimeStringMatch(expected, candidate)
}

func (a *APIServer) loadACPAPIToken() (string, bool) {
	if a == nil || a.scannerCfg == nil {
		return "", false
	}
	path := filepath.Join(a.scannerCfg.DataDir, "acp", ".token")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return "", false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", false
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return "", false
	}
	body, err := safefile.ReadRegularFileBounded(path, 16<<10)
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(string(body))
	return token, token != ""
}

func (a *APIServer) acpScopedTokenReady() bool {
	if a == nil || a.scannerCfg == nil {
		return false
	}
	key := a.scannerCfg.DeploymentMode + "\x00" + a.scannerCfg.DataDir
	now := time.Now()
	a.acpReadinessMu.Lock()
	defer a.acpReadinessMu.Unlock()
	if key == a.acpReadinessKey && now.Sub(a.acpReadinessCheckedAt) < 500*time.Millisecond {
		return a.acpReadinessValue
	}
	ready := a.acpScopedTokenReadyUncached()
	a.acpReadinessKey = key
	a.acpReadinessCheckedAt = now
	a.acpReadinessValue = ready
	return ready
}

func (a *APIServer) acpScopedTokenReadyUncached() bool {
	if managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		return acp.EnterpriseCredentialsReady(a.scannerCfg.DataDir)
	}
	path := filepath.Join(a.scannerCfg.DataDir, "acp", ".token")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return false
	}
	permissionsSafe := runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
	return permissionsSafe && safefile.ValidatePrivateFile(path) == nil
}
