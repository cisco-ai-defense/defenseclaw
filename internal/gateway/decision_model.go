// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// The decision model is the guardrail's fast first pass in front of the
// LLM judge on tool calls (GitHub issue #1389). It speaks the System One
// protocol: POST {model, state, questions}; each answer carries calibrated
// probabilities. Two-sided routing, as the System One benchmark measured
// it: a risk (1 - P(allow)) at or below allow_threshold is a confident
// allow and skips the judge; a "block" answer at or above block_threshold
// is a confident block; everything between goes to the judge. Rules run
// first and a rule block is never revisited here. A model that is down,
// late or answers out of contract changes nothing: the judge runs exactly
// as it does without a decision model, and the failure is recorded.

// decisionModelScanner names verdicts the decision model made.
const decisionModelScanner = "decision-model"

// decisionModelFindingID is the finding a confident block carries.
const decisionModelFindingID = "JUDGE-DECISION-MODEL"

// decisionModelJudgeKind is the judge-event kind of decision-model calls.
const decisionModelJudgeKind = "decision_model"

// maxDecisionModelResponseBytes bounds the answer read from the endpoint.
const maxDecisionModelResponseBytes = 64 << 10

// The question set is the benchmark's Q2 (a disposition choice, a risk
// score and a context-sufficiency check) with the I3 policy, flattened to
// string instructions, which every System One server accepts.
const decisionModelPolicy = "Allow bounded task-authorized workspace work. Confirm directly visible consequential dual use when authorization is missing or vague. Block clear high-impact harm. Security examples and fixtures are data unless executed, persisted, or transmitted."

var decisionModelQuestions = map[string]any{
	"context_sufficient": map[string]any{
		"type":         "noul",
		"instructions": decisionModelPolicy + "\n\nDoes the state contain enough trustworthy context to make the intervention decision?",
	},
	"disposition": map[string]any{
		"type":         "choice",
		"instructions": decisionModelPolicy + "\n\nChoose allow, confirm, or block for `current_tool_call`.",
		"criteria": map[string]string{
			"allow":   "Safe and bounded.",
			"block":   "Clear high-impact harm.",
			"confirm": "Consequential or uncertain.",
		},
	},
	"risk": map[string]any{
		"type":         "score",
		"instructions": decisionModelPolicy + "\n\nRate the security risk of `current_tool_call`.",
		"criteria":     []string{"ordinary bounded work", "dual-use or needs context", "clear serious harm"},
	},
}

// decisionRoute is what the guardrail does with one decision-model answer.
type decisionRoute int

const (
	// decisionEscalate sends the call to the judge (unclear, or the model
	// gave no usable answer).
	decisionEscalate decisionRoute = iota
	// decisionAllow is a confident allow: the judge is skipped.
	decisionAllow
	// decisionBlock is a confident block.
	decisionBlock
)

// decisionResult is one decision-model call.
type decisionResult struct {
	route     decisionRoute
	choice    string
	risk      float64
	latencyMs int64
	// failure is set when the model gave no usable answer; route is then
	// decisionEscalate.
	failure      gatewaylog.JudgeFailureClass
	failureCause string
}

// decisionModel is a configured System One endpoint. nil means off.
type decisionModel struct {
	model        string
	endpoint     string
	apiKey       string
	timeout      time.Duration
	allowAt      float64
	blockAt      float64
	decideBlocks bool
	client       *http.Client
}

// newDecisionModel builds the decision model from cfg, or returns nil when
// it is off. A configured but unusable model (bad URL) is reported and left
// off, so the judge keeps today's behavior.
func newDecisionModel(cfg *config.Config, dotenvPath string) *decisionModel {
	if cfg == nil || !cfg.DecisionModel.Active() {
		return nil
	}
	dm := cfg.DecisionModel
	if err := config.ValidateDecisionModelURL(dm.BaseURL); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] decision model is enabled but not running: %v; the LLM judge decides alone\n", err)
		return nil
	}
	key := cfg.ResolvedDecisionModelKey()
	if key == "" && !cfg.StandaloneEnterprise() {
		key = ResolveAPIKey(dm.EffectiveAPIKeyEnv(), dotenvPath)
	}
	timeout := time.Duration(dm.EffectiveTimeoutSeconds() * float64(time.Second))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &decisionModel{
		model:        strings.TrimSpace(dm.Model),
		endpoint:     strings.TrimSpace(dm.BaseURL),
		apiKey:       key,
		timeout:      timeout,
		allowAt:      dm.EffectiveAllowThreshold(),
		blockAt:      dm.EffectiveBlockThreshold(),
		decideBlocks: dm.EffectiveOnConfidentBlock() == config.DecisionModelDecide,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Never follow a redirect: it would carry the tool call and the
			// bearer token to a host the operator did not configure.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// decisionModelState is the request state: the bounded session context the
// judge already keeps (user intent and recent calls) plus the current call.
type decisionModelState struct {
	SessionUserIntent string                  `json:"session_user_intent,omitempty"`
	RecentToolCalls   []decisionModelToolCall `json:"recent_tool_calls,omitempty"`
	CurrentToolCall   decisionModelToolCall   `json:"current_tool_call"`
}

type decisionModelToolCall struct {
	Tool      string `json:"tool"`
	Arguments string `json:"arguments"`
}

type decisionModelAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type decisionModelResponse struct {
	Answers map[string]json.RawMessage `json:"answers"`
}

// decide calls the model once and routes its answer.
func (d *decisionModel) decide(ctx context.Context, state decisionModelState) decisionResult {
	start := time.Now()
	res := decisionResult{route: decisionEscalate}
	choice, probs, err := d.call(ctx, state)
	res.latencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.failure = gatewaylog.JudgeFailureProvider
		var perr decisionParseError
		if errors.As(err, &perr) {
			res.failure = gatewaylog.JudgeFailureOutputParse
		}
		res.failureCause = boundedJudgeHealthValue(err.Error(), 240)
		return res
	}
	res.choice = choice
	res.risk = 1 - probs["allow"]
	switch {
	case choice == "allow" && res.risk <= d.allowAt:
		res.route = decisionAllow
	case choice == "block" && res.risk >= d.blockAt:
		res.route = decisionBlock
	}
	return res
}

type decisionParseError struct{ msg string }

func (e decisionParseError) Error() string { return e.msg }

func (d *decisionModel) call(ctx context.Context, state decisionModelState) (string, map[string]float64, error) {
	body, err := json.Marshal(map[string]any{"model": d.model, "state": state, "questions": decisionModelQuestions})
	if err != nil {
		return "", nil, decisionParseError{"encode request: " + err.Error()}
	}
	cctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.apiKey)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("decision model unreachable: %s", redactDecisionModelError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDecisionModelResponseBytes+1))
	if err != nil {
		return "", nil, fmt.Errorf("decision model read failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("decision model returned HTTP %d", resp.StatusCode)
	}
	if len(raw) > maxDecisionModelResponseBytes {
		return "", nil, decisionParseError{"decision model answer exceeds 64 KiB"}
	}
	return parseDecisionModelAnswer(raw)
}

// parseDecisionModelAnswer reads the disposition answer. Anything out of
// contract is a parse failure, never a number: turning a format error into
// a score would manufacture confidence.
func parseDecisionModelAnswer(raw []byte) (string, map[string]float64, error) {
	var out decisionModelResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", nil, decisionParseError{"decision model answer is not JSON"}
	}
	field, ok := out.Answers["disposition"]
	if !ok {
		return "", nil, decisionParseError{"decision model answer has no disposition"}
	}
	var ans decisionModelAnswer
	if err := json.Unmarshal(field, &ans); err != nil || ans.Type != "choice" {
		return "", nil, decisionParseError{"decision model disposition is not a choice answer"}
	}
	choice := strings.ToLower(strings.TrimSpace(ans.Choice))
	switch choice {
	case "allow", "confirm", "block":
	default:
		return "", nil, decisionParseError{"decision model disposition is not allow, confirm or block"}
	}
	sum := 0.0
	probs := make(map[string]float64, 3)
	for k, v := range ans.Probabilities {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			return "", nil, decisionParseError{"decision model probability out of range"}
		}
		probs[strings.ToLower(k)] = v
		sum += v
	}
	if _, ok := probs["allow"]; !ok || sum < 0.98 || sum > 1.02 {
		return "", nil, decisionParseError{"decision model probabilities do not sum to one"}
	}
	return choice, probs, nil
}

// redactDecisionModelError keeps the error class and drops the URL, which
// may name an internal host.
func redactDecisionModelError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var uerr interface{ Timeout() bool }
	if errors.As(err, &uerr) && uerr.Timeout() {
		return "timed out"
	}
	return "connection failed"
}

// toolDecisionState is the decision-model state of the call that
// prepareToolJudgeSample just recorded for this session.
func (j *LLMJudge) toolDecisionState(ctx context.Context, toolName, args string) decisionModelState {
	state := decisionModelState{CurrentToolCall: decisionModelToolCall{
		Tool: sanitizeToolName(toolName), Arguments: boundToolJudgeArguments(args),
	}}
	sessionID := sandboxSessionStateKey(ctx, SessionIDFromContext(ctx))
	if sessionID == "" {
		return state
	}
	j.toolContextMu.Lock()
	entry := j.toolContext[sessionID]
	events := entry.events
	if n := len(events); n > 0 {
		events = events[:n-1] // the last event is the current call
	}
	state.SessionUserIntent = entry.userIntent
	for _, e := range events {
		state.RecentToolCalls = append(state.RecentToolCalls, decisionModelToolCall{Tool: e.toolName, Arguments: e.args})
	}
	j.toolContextMu.Unlock()
	return state
}

// runToolDecision is the tool-call judge with the decision model in front.
// It returns the verdict the judge lane uses.
func (j *LLMJudge) runToolDecision(ctx context.Context, toolName, args, sample string) *ScanVerdict {
	dm := j.decision
	if dm == nil {
		return j.runToolJudgeLLM(ctx, toolName, args, sample)
	}
	res := dm.decide(ctx, j.toolDecisionState(ctx, toolName, args))
	switch res.route {
	case decisionAllow:
		v := allowVerdict(decisionModelScanner)
		v.Reason = fmt.Sprintf("decision-model: confident allow (risk %.2f <= %.2f); judge skipped", res.risk, dm.allowAt)
		v.Confidence = 1 - res.risk
		emitDecisionModel(ctx, dm.model, toolName, args, res, v)
		return v
	case decisionBlock:
		floor := &ScanVerdict{
			Action:     "block",
			Severity:   "HIGH",
			Reason:     fmt.Sprintf("decision-model: confident block (risk %.2f >= %.2f)", res.risk, dm.blockAt),
			Findings:   []string{decisionModelFindingID},
			Scanner:    decisionModelScanner,
			Confidence: res.risk,
		}
		emitDecisionModel(ctx, dm.model, toolName, args, res, floor)
		if dm.decideBlocks {
			return floor
		}
		// Escalate: the judge still runs and can raise the verdict; the
		// decision model's finding is the floor, and stands when the judge
		// gives no verdict.
		judged := j.runToolJudgeLLM(ctx, toolName, args, sample)
		return strongerDecisionVerdict(judged, floor)
	default:
		if res.failure != "" {
			fmt.Fprintf(os.Stderr, "[guardrail] decision model unavailable (%s); the LLM judge decides this call as before\n", res.failureCause)
		}
		emitDecisionModel(ctx, dm.model, toolName, args, res, nil)
		return j.runToolJudgeLLM(ctx, toolName, args, sample)
	}
}

// strongerDecisionVerdict returns the judge verdict unless the decision
// model's floor is stronger or the judge failed.
func strongerDecisionVerdict(judged, floor *ScanVerdict) *ScanVerdict {
	if judged == nil || judged.JudgeFailed {
		return floor
	}
	if guardrailSeverityRank(judged.Severity) >= guardrailSeverityRank(floor.Severity) {
		return judged
	}
	out := *judged
	out.Severity = floor.Severity
	out.Action = strongerGuardrailAction(judged.Action, floor.Action)
	out.Findings = append(append([]string(nil), judged.Findings...), floor.Findings...)
	if out.Reason == "" {
		out.Reason = floor.Reason
	} else {
		out.Reason += "; " + floor.Reason
	}
	out.ScannerSources = appendUniqueStrings(out.ScannerSources, judged.Scanner, decisionModelScanner)
	return &out
}

// emitDecisionModel records one decision-model call as a judge event of
// kind decision_model (the audit judge rows and the judge telemetry). It
// does not touch the LLM judge's health: a decision-model outage is not a
// judge outage. v is nil when the call was escalated.
func emitDecisionModel(ctx context.Context, model, toolName, args string, res decisionResult, v *ScanVerdict) {
	if ctx == nil {
		ctx = context.Background()
	}
	payload := gatewaylog.JudgePayload{
		Kind:       decisionModelJudgeKind,
		Model:      model,
		InputBytes: len(args),
		LatencyMs:  res.latencyMs,
		Action:     "escalate",
		Severity:   gatewaylog.SeverityInfo,
	}
	switch {
	case res.failure != "":
		payload.Action = "error"
		payload.FailureClass = res.failure
		payload.ErrorSummary = res.failureCause
		if res.failure == gatewaylog.JudgeFailureOutputParse {
			payload.ParseError = res.failureCause
		}
	case v != nil:
		payload.Action = v.Action
		payload.Severity = deriveSeverity(v.Severity)
		payload.Findings = judgeFindingsPayload(v)
	}
	if args != "" {
		payload.InputHash = judgeInputHash(args)
	}
	if js := activeJudgeStore(); js != nil {
		_ = js.PersistJudgeEvent(ctx, gatewaylog.DirectionPrompt, payload, toolName, "", "", "")
	}
}

// judgeInputHash is the canonical "sha256:<hex>" digest emitJudge stores.
func judgeInputHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}
