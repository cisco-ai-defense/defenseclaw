// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package engine decides which configured model a request goes to. It is
// pure Go with no gateway import: the gateway hands it a Request built from
// the parsed body and the verified caller, and applies the Decision. See
// plans/r110/streams/S1/DESIGN.md sections 2, 3, 15 and 16.
package engine

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Tri is a three-valued match answer (assignmentState on the gateway side).
type Tri int

const (
	No Tri = iota
	Maybe
	Yes
)

// Caller is the identity routing may use. Only a verified caller gets a
// profile overlay or gateway-held credentials; a request header never fills
// it.
type Caller struct {
	Verified      bool
	Key           string // stable subject key (uid, SID or principal); also set for unverified callers
	Source        string // subject source name, for records
	LookupFailed  bool
	GroupsUnknown bool
	// Matches answers a profile-style match against the caller facts.
	Matches func(config.ProfileMatch) Tri
	// Actor is the Agent Substrate actor the call comes from, read from
	// its registration on the verified actor listener context (never a
	// header). Nil for a host call.
	Actor *Actor
}

// Actor is what routing.admin reads about an actor call: the
// registration key (atespace plus actor UID, the actor budget key),
// whether a person owns it, and the match.substrate facts.
type Actor struct {
	Key string
	// Person is false for an attributed actor (D3): it is charged only to
	// actor and connector budgets.
	Person                       bool
	Atespace, Template, Workload string
	// BatchID is the registration batch id (from the launcher, never a
	// header); scope batch budgets read it. Empty: not a batch call.
	BatchID string
}

// Listener names where a request arrived.
const (
	ListenerGuardrail = "guardrail"
	ListenerRouteOnly = "route_only"
)

// Credential classes of the inbound request (never the value).
const (
	CredentialNone    = "none"
	CredentialAPIKey  = "api_key"
	CredentialOAuth   = "oauth"
	CredentialBearer  = "bedrock_bearer"
	CredentialGateway = "gateway"
)

// Request is everything routing reads about one model call. Text is the
// classifier input: human-typed text only, already bounded by the caller.
type Request struct {
	Text              string
	APIFamily         string
	Connector         string
	Agent             string
	Listener          string
	Severity          string // pre-call guardrail severity, "" when none ran
	RequestedModel    string
	RequestedProvider string
	CredentialClass   string
	HasTools          bool
	ToolTurn          bool
	HasImages         bool
	LongContext       bool
	ConversationID    string
	// SensitiveText is the bounded text the decision-model check reads
	// (user and tool turns, newest first; never system prompts), and
	// SensitiveTruncated says a cap cut it (ONE BOUND RULE). StrictTier is
	// the posture of the caller guardrail profile: a truncated input is
	// judged at least at the unknown tier, which routes local only under
	// strict.
	SensitiveText      string
	SensitiveTruncated bool
	StrictTier         bool
	// ContextTurns, FirstTurn, ToolNames and ToolLoop are the
	// routing.context facts (ContextCollector.Fill): older human-typed user
	// turns newest first, the first turn when the window does not hold it,
	// the names of the tools the loop called, and whether it called any.
	// Empty unless routing.context is on.
	ContextTurns []string
	FirstTurn    string
	ToolNames    []string
	ToolLoop     bool
	// Profiles are the guardrail profiles the caller resolved to, in
	// assignment order (several when the profile meet combined them).
	Profiles      []string
	ProfileDigest string
	Caller        Caller
	// Narrowed is set by Decide while it tries candidates: routing.sensitive
	// narrowed the request (CredentialOK may relax for a keyless local
	// model then). Callers leave it false.
	Narrowed bool
}

// Backend is one routing.models entry.
type Backend struct {
	Alias        string
	Provider     string
	Model        string
	BaseURL      string
	APIs         []string
	APIKeyEnv    string
	Credential   string
	Capabilities []string
	Bedrock      *config.RoutingBedrockAuthConfig
}

// Outcome of one decision.
const (
	OutcomeApplied     = "applied"
	OutcomeFallback    = "fallback"
	OutcomeDenied      = "denied"
	OutcomePassthrough = "passthrough"
)

// Decision sources.
const (
	SourceRules        = config.RoutingClassifierRules
	SourceSystemOne    = config.RoutingClassifierSystemOne
	SourceVLLMSR       = config.RoutingClassifierVLLMSR
	SourceUserOverride = "user_override"
	SourceSticky       = "sticky"
	SourceForce        = "force"
	SourceDefault      = "default"
	// SourceSensitive is a routing.sensitive.aliases candidate tried
	// because the request is sensitive (GAP-0576).
	SourceSensitive = "sensitive"
)

// DenyCodeSensitiveLocal refuses a sensitive request that no allowed
// routing.sensitive.aliases model can serve. Such a request is never sent
// to the original provider or to another alias (GAP-0576), on OSS and on
// managed hosts.
const DenyCodeSensitiveLocal = "routing_sensitive_local_unavailable"

// SensitiveLocalDeny is the refusal of a sensitive request: source is what
// found it sensitive, cause why no local model can take it.
func SensitiveLocalDeny(source, cause string) *DenyReason {
	if source == "" {
		source = "routing.sensitive"
	}
	return &DenyReason{Code: DenyCodeSensitiveLocal, Message: "this request holds sensitive data (found by " + source +
		"), so routing.sensitive keeps it on a local model (routing.sensitive.aliases); " + cause +
		", so DefenseClaw refused it instead of sending it to a cloud model"}
}

// Failure codes (closed set; metric labels).
const (
	FailureNone           = "none"
	FailureTimeout        = "timeout"
	FailureUpstreamStatus = "upstream_status"
	FailureDecode         = "decode_failure"
	FailureConfig         = "configuration_failure"
	FailureFiltered       = "filtered"
	FailureBreakerOpen    = "breaker_open"
	FailureLowConfidence  = "low_confidence"
	FailureNoCandidate    = "no_candidate"
)

// DenyReason is a routing refusal: a managed admin rule, or a sensitive
// request no local model can serve (DenyCodeSensitiveLocal, every host).
type DenyReason struct {
	Code    string
	Message string
}

// Decision is the routing outcome for one request.
type Decision struct {
	Outcome    string
	Backend    *Backend // nil unless Outcome is applied
	Source     string
	Category   string
	RuleID     string
	Candidate  string
	FilteredBy string
	// NoCredential lists the aliases the policy allows that the request
	// could not use for lack of a gateway credential (Gate then says so
	// instead of blaming the administrator, rel-1-0-10 GAP-0921).
	NoCredential []string
	// OtherUnfit is true when another allowed alias was dropped for a reason
	// that is not a credential (capability, API family or endpoint), so a missing
	// credential is not the whole story.
	OtherUnfit   bool
	FailureCode  string
	Confidence   float64
	Deny         *DenyReason
	Warnings     []string
	RuleIDs      []string
	ChargeKeys   []string
	PolicyDigest string
	Latency      time.Duration
	// Sensitive records how the sensitive-data narrowing was decided.
	Sensitive SensitiveOutcome

	verdict AdminVerdict
}

// SensitiveNarrowed reports whether routing.sensitive narrowed the decision:
// its only allowed exits are then the routing.sensitive.aliases models. A
// soft decision (the check could not answer, or a strict truncated input)
// prefers the local models but is never refused for lacking one.
func (d Decision) SensitiveNarrowed() bool { return d.Sensitive.Source != "" && !d.Sensitive.Soft }

// ClassifyInput is what a classifier sees: no identity, no credentials.
type ClassifyInput struct {
	// Text is the newest human-typed user turn, or with routing.context
	// the bounded context text (ClassifierTextLimit at most).
	Text           string
	APIFamily      string
	Connector      string
	RequestedModel string
	HasTools       bool
	ToolTurn       bool
	HasImages      bool
	LongContext    bool
	ToolLoop       bool
	// Signals are the keyword signals that matched Text (and, with
	// routing.context, the tool-name line).
	Signals map[string]bool
	// Categories are the category names of the effective policy, sorted
	// (the choices a category classifier such as systemone picks from).
	Categories []string
}

// ClassifyResult is a classifier answer. Aliases are candidates in order;
// when empty, Category maps through the policy categories.
type ClassifyResult struct {
	Category   string
	Aliases    []string
	Confidence float64 // 0..1; -1 when the classifier gives none
	RuleID     string
}

// Classifier is one routing classifier (rules, systemone, vllm_sr).
type Classifier interface {
	Name() string
	Classify(ctx context.Context, in ClassifyInput) (ClassifyResult, error)
}

// ClassifierError carries a closed failure code.
type ClassifierError struct {
	Code string
	Err  error
}

func (e *ClassifierError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *ClassifierError) Unwrap() error { return e.Err }

// Sources of a sensitive narrowing (SensitiveOutcome.Source).
const (
	SensitiveSourceGuardrail = "guardrail"
	SensitiveSourceSignal    = "signal"
	// SensitiveSourceSticky: an earlier turn of the same conversation (same
	// caller, connector and agent session id) was sensitive, and the later
	// turns carry it in their history.
	SensitiveSourceSticky = "sticky"
)

// SensitiveOutcome says what decided the sensitive narrowing of one
// request. Source is empty when nothing narrowed; otherwise guardrail (the
// regex and rule floor), signal (a routing keyword signal), sticky (an
// earlier positive of the conversation), or the checker name
// (decision_model or judge). Reason is positive, unavailable:<code>,
// truncated or clear. Checked is true when the checker ran.
type SensitiveOutcome struct {
	Source       string
	Reason       string
	Checked      bool
	CheckFailure string
	CheckLatency time.Duration
	// Soft: the local models are preferred, not required (an unavailable
	// check under on_unavailable: local, or a strict truncated input).
	Soft bool
}

// SensitiveInput is what a sensitivity checker sees: bounded text, no
// identity, no credentials.
type SensitiveInput struct {
	Text       string
	Truncated  bool
	Definition string
	Connector  string
}

// SensitiveChecker answers one question: does the text hold sensitive
// data. It returns a ClassifierError with a closed failure code when it
// cannot answer; the engine then applies routing.sensitive.on_unavailable.
type SensitiveChecker interface {
	Name() string
	Check(ctx context.Context, in SensitiveInput) (bool, error)
}
