// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type verifiedUserScopedIdentityContextKey struct{}

// handleForeignHookSession keeps the standalone session snapshot in the
// gateway's data directory. The namespace comes only from hook-socket peer
// credentials or a per-user hook token authenticated by tokenAuth.
//
// On a standalone host an exchange holds its account's removal lock shared
// (enterprisepolicy.LockForeignHookAccountExchange) from before it reads the
// record key and the guardian's removals until its answer is written, and
// answers allow only within foreignHookExchangeHold of taking it. A hook
// removal of the account (the guardian holds the lock exclusively) therefore
// either waits for this answer or makes this exchange deny; other accounts
// never wait on it (GAP-0348, GAP-0414).
func (a *APIServer) handleForeignHookSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.userScopedCredentialsRequired() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	connector := strings.TrimPrefix(r.URL.Path, enterprisepolicy.ForeignHookSessionPathPrefix)
	if connector == "" || strings.Contains(connector, "/") || authenticatedHookConnector(r.Context()) != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_unverified")
		return
	}
	identity := ""
	if peer, ok := managedHookPeerFromContext(r.Context()); ok {
		identity = strconv.Itoa(peer.UID)
	} else {
		identity, _ = r.Context().Value(verifiedUserScopedIdentityContextKey{}).(string)
	}
	if identity == "" {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_identity_unverified")
		return
	}
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		writeManagedHookRefusal(w, http.StatusServiceUnavailable, "foreign_hook_session_store_unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var exchange enterprisepolicy.SessionExchange
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&exchange); err != nil {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	if exchange.Key.Connector != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_mismatch")
		return
	}
	stateDir := enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity)
	// Each identity has its own store, so only that identity's exchanges
	// are serialized; another account's exchange never waits on this one.
	unlock := sync.OnceFunc(a.foreignHookSessionLocks.lock(stateDir))
	defer unlock()
	removalsDir := managed.HookGuardianAuthorizationDir(dataDir)
	// The deadline of an allow is set before the account's lock is asked
	// for, not once it is held. This exchange takes the gate before any
	// removal of the account that it holds the lock against, and a removal
	// gives up waiting for it only ForeignHookRemovalDrainWait (longer than
	// the hold) after it took the gate: so a removal goes on past this
	// exchange only once answerBy passed.
	answerBy := time.Now().Add(foreignHookExchangeHold)
	// Only a standalone gateway gets here (userScopedCredentialsRequired),
	// so every exchange takes its account's removal lock.
	var lockErr error
	release := func() {}
	ctx, cancel := context.WithTimeout(r.Context(), foreignHookExchangeWait)
	if held, err := foreignHookAccountExchangeLock(ctx, dataDir, identity); err != nil {
		lockErr = err
	} else {
		release = held
	}
	cancel()
	defer release()
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(removalsDir, identity)
	// A removal in progress keeps its own reason through the join
	// (ApplyForeignHookRemovals checks it first).
	removalsErr := errors.Join(lockErr, ledgerErr)
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Removals:     removals,
		RemovalsErr:  removalsErr,
		Now:          time.Now(),
	})
	if !decision.Deny && !time.Now().Before(answerBy) {
		// Too late to answer allow: a removal of the account may already
		// have stopped waiting for this exchange.
		decision = enterprisepolicy.ApplyForeignHookRemovals(decision, exchange.Key, nil, errForeignHookExchangeExpired, time.Now())
	}
	if decision.Deny {
		// A denial cannot become an allow when the guardian commits a
		// removal, so neither lock is held through the audit export or the
		// response write.
		release()
		unlock()
		a.auditForeignHookSessionDenial(r.Context(), connector, exchange, decision)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
		return
	}
	if refusal := writeFencedForeignHookAllow(w, decision, answerBy); refusal != "" {
		release()
		unlock()
		writeManagedHookRefusal(w, http.StatusServiceUnavailable, refusal)
	}
}

// errForeignHookExchangeExpired is an exchange that could not answer within
// foreignHookExchangeHold of taking its account's removal lock.
var errForeignHookExchangeExpired = errors.New("the exchange did not answer in time")

// foreignHookExchangeWait bounds how long an exchange waits for its
// account's removal lock (enterprisepolicy.ForeignHookExchangeWait),
// foreignHookExchangeHold how long after taking it the exchange may answer
// allow (enterprisepolicy.ForeignHookExchangeHold), and
// foreignHookFencedWriteTimeout an allow's response write, so a client that
// stops reading its response does not hold the lock for long. A response
// that fits the socket buffer is written without the client reading; one the
// client does not take in time is cut, and the client's hook fails closed on
// the incomplete response. foreignHookAccountExchangeLock takes the lock
// (replaceable in tests).
var (
	foreignHookExchangeWait        = enterprisepolicy.ForeignHookExchangeWait
	foreignHookExchangeHold        = enterprisepolicy.ForeignHookExchangeHold
	foreignHookFencedWriteTimeout  = 250 * time.Millisecond
	foreignHookAccountExchangeLock = enterprisepolicy.LockForeignHookAccountExchange
)

// writeFencedForeignHookAllow writes an allow and flushes it to the
// connection within foreignHookFencedWriteTimeout, and never past answerBy.
// It returns a refusal reason, having written nothing, when the connection
// cannot bound the write or answerBy has passed: the caller then refuses the
// call instead of answering an allow that a removal no longer waits for.
// A write cut at the deadline leaves the expired deadline in place, so the
// server's own finishing writes fail at once too.
func writeFencedForeignHookAllow(w http.ResponseWriter, decision enterprisepolicy.GuardDecision, answerBy time.Time) string {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(decision); err != nil {
		return "foreign_hook_response_unbounded"
	}
	deadline := time.Now().Add(foreignHookFencedWriteTimeout)
	if answerBy.Before(deadline) {
		deadline = answerBy
	}
	if !time.Now().Before(deadline) {
		return "foreign_hook_removal_fence_expired"
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return "foreign_hook_response_unbounded"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body.Bytes()); err != nil {
		return ""
	}
	if err := controller.Flush(); err != nil {
		return ""
	}
	// A keep-alive connection serves the caller's next request: clear the
	// deadline only after the whole allow has reached it.
	_ = controller.SetWriteDeadline(time.Time{})
	return ""
}

// foreignHookAuditReasonLimit bounds the reason an audit row repeats, and
// foreignHookAuditFieldLimit each finding field (the session store clips
// the same fields to 512 bytes). The caller sends these values, so an
// enrolled user must not be able to write rows of any size.
const (
	foreignHookAuditReasonLimit = 2048
	foreignHookAuditFieldLimit  = 512
)

// foreignHookDenialRuleID is the rule ID every foreign-hook guard denial
// carries. The guard matches no rule pack, so its blocks had action and
// severity but no rule_id on their tool, agent and apply_guardrail spans and
// in Galileo, and a dashboard could not tell them from any other block
// (GAP-2610). The reason stays on the audit row and the hook decision record.
const foreignHookDenialRuleID = "ENTERPRISE-FOREIGN-HOOK-BLOCKED"

// clipForeignHookAuditField drops control characters and bounds value to
// limit bytes on a rune boundary.
func clipForeignHookAuditField(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	return truncateToRuneBoundary(value, limit)
}

// auditForeignHookSessionDenial writes one connector-hook audit row for a
// tool call the foreign-hook guard denies, when the exchange records a
// session block, enforces an earlier one, or denies the call alone, so the
// administrator sees each denial with the connector, the user and the file,
// like other blocks, instead of only the guardian's periodic journal
// summary. The guard's own hook in the agent enforces the decision; this
// row is its record.
func (a *APIServer) auditForeignHookSessionDenial(
	ctx context.Context,
	connectorName string,
	exchange enterprisepolicy.SessionExchange,
	decision enterprisepolicy.GuardDecision,
) {
	if a == nil {
		return
	}
	// The denial names the caller like the allow rows of the same agent: the
	// agent identity (agt-) from the verified user and the connector
	// (GAP-1039), and the session and session instance (ais-) of the
	// exchange's session through the same context enrichment as every hook
	// call, and the session's agent (its live hook snapshot, else its root
	// agent, as the session's own rows), so a SIEM joins the block to the
	// session and agent it stopped (GAP-1903). An exchange with no session
	// (an OpenCode denial keyed on the agent process) still names the agt-.
	ctx = enrichAgentHookContext(ctx, agentHookRequest{
		ConnectorName: connectorName,
		SessionID:     strings.TrimSpace(exchange.Key.Session),
	})
	ctx = a.contextWithSessionAgentV8(ctx, connectorName)
	block := "call"
	switch {
	case strings.Contains(decision.Reason, "cannot verify this agent session's hook record"):
		block = "session_record_unavailable"
	case exchange.SessionStart && exchange.Decision.Deny:
		block = "session_recorded"
	case !exchange.Decision.Deny:
		block = "session_enforced"
	}
	extra := map[string]string{
		"guard":         "foreign_hook_session",
		"session_block": block,
		"findings":      strconv.Itoa(len(decision.Findings)),
	}
	for _, finding := range decision.Findings {
		if finding.Allowed || finding.Path == "" {
			continue
		}
		extra["file"] = clipForeignHookAuditField(finding.Path, foreignHookAuditFieldLimit)
		if finding.Scope != "" {
			extra["scope"] = clipForeignHookAuditField(finding.Scope, foreignHookAuditFieldLimit)
		}
		if finding.Digest != "" {
			extra["digest"] = clipForeignHookAuditField(finding.Digest, foreignHookAuditFieldLimit)
		}
		if finding.Reason != "" {
			extra["finding_reason"] = clipForeignHookAuditField(finding.Reason, foreignHookAuditFieldLimit)
		}
		break
	}
	reason := clipForeignHookAuditField(decision.Reason, foreignHookAuditReasonLimit)
	env := HookAuditEnvelope{
		Connector:  connectorName,
		Event:      "foreign_hook_session",
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "HIGH",
		Mode:       "action",
		Reason:     reason,
		RuleIDs:    []string{foreignHookDenialRuleID},
		WouldBlock: true,
		Enforced:   true,
		Extra:      extra,
	}
	// The denial is a guardrail block like any other, so it is exported as
	// one: a hook decision record naming the user, the connector-hook block
	// metrics and an apply_guardrail block span. Before, it reached only the
	// audit row, and dashboards, alerts and traces that count blocks never
	// saw it (GAP-2044).
	a.emitForeignHookSessionDenialV8(ctx, connectorName, exchange, env)
	if a.logger != nil {
		_ = a.logConnectorHookAuditEnvelope(ctx, env)
	}
}

// emitForeignHookSessionDenialV8 exports one foreign-hook guard denial
// through the same v8 families as a connector-hook block.
func (a *APIServer) emitForeignHookSessionDenialV8(
	ctx context.Context,
	connectorName string,
	exchange enterprisepolicy.SessionExchange,
	env HookAuditEnvelope,
) {
	if ctx == nil {
		return
	}
	defer func() { _ = recover() }()
	// The hook event the agent sent names the decision's lifecycle event
	// (tool_start for a tool call), as for any other hook block; without it
	// every denial said lifecycle.event "event" (GAP-2216).
	event := clipForeignHookAuditField(strings.TrimSpace(exchange.Event), foreignHookAuditFieldLimit)
	req := agentHookRequest{
		ConnectorName: connectorName,
		HookEventName: firstNonEmpty(event, env.Event),
		SessionID:     exchange.Key.Session,
	}
	// An enforced block, as a hook response reports it: would_block marks an
	// observe-mode decision only.
	resp := agentHookResponse{
		Action: env.Action, RawAction: env.RawAction, Severity: env.Severity,
		Mode: env.Mode, Reason: env.Reason, RuleIDs: env.RuleIDs,
	}
	a.emitHookDecisionObservabilityV8(ctx, req, resp, env, false)
	// A denied tool call carries the block on its tool span, like any other
	// blocked call, so every trace destination (Galileo included) shows it;
	// a session or prompt event gets an apply_guardrail span named for what
	// was denied, never "tool_call" (GAP-2142).
	targetType, tool := foreignHookSessionDenialTarget(exchange)
	if tool != "" {
		if outcome, ok := hookGuardrailOutcomeFor(resp.Action, resp.Severity, resp.Reason, env.RuleIDs); ok {
			meta := hookLLMEventMeta(ctx, connectorName, exchange.Key.Session, "", "", connectorName, "", "", "", nil)
			meta = applyHookEventMeta(meta, event, nil)
			meta.Guardrail = outcome
			meta.LifecycleOutcome = "blocked"
			a.emitHookToolSpanFor(ctx, meta, tool, "", "", outcome.Reason, nil)
			return
		}
	}
	a.emitGuardrailApplyTraceV8(ctx, connectorName, "", targetType, &ToolInspectVerdict{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Reason: resp.Reason, Mode: resp.Mode,
	}, 0, hookEvaluationContext{RuleIDs: env.RuleIDs})
}

// foreignHookSessionDenialTarget names what a foreign-hook denial was for:
// the apply_guardrail target type, and the tool when the event is a tool
// call. An exchange from a hook that sends no event name keeps the earlier
// "tool_call" label unless it is a session start.
func foreignHookSessionDenialTarget(exchange enterprisepolicy.SessionExchange) (targetType, tool string) {
	event := strings.TrimSpace(exchange.Event)
	if event == "" {
		if exchange.SessionStart {
			return "session", ""
		}
		return "tool_call", ""
	}
	switch canonicalHookLifecycleEvent(event) {
	case "tool_start", "tool_end":
		tool = clipForeignHookAuditField(strings.TrimSpace(exchange.Tool), foreignHookAuditFieldLimit)
		if tool == "" {
			// Cursor's shell, MCP and file events name no tool.
			tool = "tool"
			if strings.EqualFold(event, "beforeShellExecution") {
				tool = "shell"
			}
		}
		return "tool_call", tool
	case "session_start", "session_end", "subagent_start", "subagent_stop":
		return "session", ""
	case "turn_start":
		return "prompt", ""
	case "turn_end":
		return "completion", ""
	case "compact_start", "compact_end":
		return "compaction", ""
	}
	// Cursor's workspaceOpen opens the session and afterAgentThought is
	// agent output; neither is a lifecycle event of its own (GAP-2216).
	switch canonicalEvent(event) {
	case "workspaceopen":
		return "session", ""
	case "afteragentthought":
		return "completion", ""
	}
	if exchange.SessionStart {
		return "session", ""
	}
	if isPromptLikeEvent(event) {
		return "prompt", ""
	}
	return "event", ""
}

// foreignHookRemovalSource reads the guardian's ledger for each call. A
// pending cleanup denial must be visible before its file removal even when
// the replacement ledger has the same size and timestamp as the last one.
type foreignHookRemovalSource struct{}

// forIdentity returns the removals the guardian recorded for one caller.
// A missing ledger records none; one that fails its trust check or does not
// parse is an error, which denies the call.
func (foreignHookRemovalSource) forIdentity(dir, identity string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	removals, err := readForeignHookRemovals(path)
	if err != nil {
		return nil, err
	}
	var out []enterprisepolicy.ForeignHookRemoval
	for _, removal := range removals {
		if canonical, ok := connector.CanonicalUserScopedIdentity(removal.Identity); ok && canonical == identity {
			out = append(out, removal)
		}
	}
	return out, nil
}

// The guardian replaces the ledger while exchanges run. A read that meets
// the replacement on Windows is tried again foreignHookRemovalsBusyRetries
// times, foreignHookRemovalsBusyDelay apart, well within an exchange's
// hold, instead of denying the call.
const (
	foreignHookRemovalsBusyRetries = 20
	foreignHookRemovalsBusyDelay   = 5 * time.Millisecond
)

func readForeignHookRemovals(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	for attempt := 0; ; attempt++ {
		removals, err := readForeignHookRemovalsOnce(path)
		if err == nil || attempt == foreignHookRemovalsBusyRetries || !foreignHookRemovalsReadBusy(err) {
			return removals, err
		}
		time.Sleep(foreignHookRemovalsBusyDelay)
	}
}

func readForeignHookRemovalsOnce(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	if err := validateManagedGuardianAuthorization(path, "hook guardian foreign-hook removals"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, enterprisepolicy.ForeignHookRemovalsMaxBytes+1))
	if err != nil {
		return nil, err
	}
	return enterprisepolicy.ParseForeignHookRemovals(data)
}
