// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"net/http"
	"time"
)

// CallRole says who made a model call.
type CallRole string

const (
	RoleAgent            CallRole = "agent"
	RoleJudge            CallRole = "judge"
	RoleDecisionModel    CallRole = "decision_model"
	RoleAIDefense        CallRole = "ai_defense"
	RoleRouterClassifier CallRole = "router_classifier"
)

// Route decision values (RouteFacts.Decision).
const (
	DecisionApplied     = "applied"
	DecisionFallback    = "fallback"
	DecisionDenied      = "denied"
	DecisionNone        = "none"        // router off
	DecisionPassthrough = "passthrough" // route-only listener, model unchanged
)

// RouteFacts is why a call went where it went. S1 fills it.
type RouteFacts struct {
	Decision       string // applied | fallback | denied | none | passthrough
	Source         string // rules | systemone | vllm_sr | profile_default | admin_default | ""
	Category       string // bounded label from the classifier, "" if none
	RuleID         string // routing.decisions[].name or routing.admin.rules[].id that picked it
	FilteredBy     string // profile | admin | guardrail | ""
	FallbackReason string // closed set of route failure codes
	Confidence     float64
	CandidateAlias string
	SelectedAlias  string
	RouteLatency   time.Duration
}

// CallFacts is what the caller knows before the upstream call. All plain
// values: no prompt text, no headers, no keys.
type CallFacts struct {
	RequestID, TraceID string
	Listener           string // guardrail | route_only
	Connector, Surface string
	APIFamily          APIFamily
	CallRole           CallRole
	Streaming          bool

	RequestedProvider, RequestedModel string
	SelectedProvider, SelectedModel   string

	Route                      RouteFacts
	ProfileName, ProfileDigest string

	// Subject and Groups come from a verified caller only. Groups never leave
	// the endpoint on exported records: only the local store and the admin
	// API read them.
	Subject string
	// SubjectKind is a useridentity kind: posix_uid or windows_sid. Writers
	// (the proxy, the route-only listener) and readers (/usage, the own-status
	// block) must use the same form, because it is the owner key of a usage row.
	// OwnerID also derives it from the subject when the kind is anything else.
	SubjectKind      string
	Groups           []string
	IdentityVerified bool

	// Correlation of a call imported from the OTLP telemetry of the agent
	// (Engine.RecordNative): the session, turn and agent it joined on the hook
	// rail, the agent prompt id and the provider request id. Proxied calls
	// leave them empty; their records correlate through the request id.
	SessionID, TurnID, AgentID      string
	ModelRequestID, ModelResponseID string

	StartedAt time.Time

	// ChargeKeys are the budget keys the admin routing verdict says this call
	// is charged to (S11 AdminVerdict.ChargeKeys). The record keeps them and the
	// SpendSink charges the resolved call cost to each of them.
	ChargeKeys []string
}

// ParsedUsage is usage the caller already parsed (the Bifrost chat path). It
// wins over parsing the bytes. Has says which counts are real; a caller that
// leaves Has zero gets the non-zero counts treated as present.
type ParsedUsage struct {
	Input, Output, CacheRead, CacheCreation, Reasoning int64
	Has                                                Has
	ResponseModel                                      string
	Source                                             string
}

func (p ParsedUsage) usage() Usage {
	u := Usage{
		Input: p.Input, Output: p.Output, CacheRead: p.CacheRead, CacheCreation: p.CacheCreation, Reasoning: p.Reasoning,
		Has: p.Has, ResponseModel: p.ResponseModel, Source: p.Source,
	}
	if u.Has == 0 {
		if p.Input != 0 || p.Output != 0 {
			u.Has |= HasInput | HasOutput
		}
		if p.CacheRead != 0 {
			u.Has |= HasCacheRead
		}
		if p.CacheCreation != 0 {
			u.Has |= HasCacheCreation
		}
		if p.Reasoning != 0 {
			u.Has |= HasReasoning
		}
	}
	if u.Has != 0 && u.Source == "" {
		u.Source = SourceProvider
	}
	u.seal()
	return u
}

// Label is one metric label.
type Label struct{ Key, Value string }

// Record is one finished model call: the facts, the usage, the cost.
type Record struct {
	Facts     CallFacts
	Usage     Usage
	Cost      Cost
	Status    int
	Outcome   string // completed | failed | cancelled
	ErrorType string
	TTFB      time.Duration
	Total     time.Duration
	EndedAt   time.Time
	// Labels are the bounded metric labels for this call, in the configured
	// order. They carry no identity.
	Labels []Label
	// ModelKey and ProviderKey are the bounded model and provider of the call:
	// the price-table entry that priced it (else other) and a plain lower-case
	// provider name (else other). The local store and the labels key on these,
	// never on the client-chosen model string.
	ModelKey, ProviderKey string
}

// DropSource is a sink that counts records it lost (cumulative, by kind).
type DropSource interface {
	DropTotals() map[string]int64
}

// DropReporter is a sink that exports how many records were lost since the
// last report (defenseclaw.tokenomics.dropped).
type DropReporter interface {
	ReportDrops(n int64)
}

// Recorder is what the proxy and the connectors call. Begin is called once
// per upstream call after the route is final and before the request is sent.
type Recorder interface {
	Begin(ctx context.Context, f CallFacts) Call
}

// Call is one in-flight model call. Methods never block, never return an
// error and are safe on the no-op call.
type Call interface {
	UpstreamHeader(status int, h http.Header)
	Chunk(p []byte) // streaming: response bytes exactly as forwarded; not retained
	Body(p []byte)  // non-streaming: the full response body
	Usage(u ParsedUsage)
	// End finishes the call exactly once and returns the record so the
	// caller can put token and cost attributes on its model span. Further
	// calls return the same record.
	End(err error) Record
}

// Sink receives finished records on the engine worker goroutine. During a
// disable and enable of the engine an old worker may drain while a new one
// starts, so a sink must be safe for concurrent Emit. A sink must not retain
// the Record slices it does not own and must not export Facts.Groups.
type Sink interface {
	Emit(ctx context.Context, rec Record)
}

type noopRecorder struct{}

func (noopRecorder) Begin(context.Context, CallFacts) Call { return noopCall{} }

type noopCall struct{}

func (noopCall) UpstreamHeader(int, http.Header) {}
func (noopCall) Chunk([]byte)                    {}
func (noopCall) Body([]byte)                     {}
func (noopCall) Usage(ParsedUsage)               {}
func (noopCall) End(error) Record                { return Record{} }

// Noop is the recorder used when tokenomics is off: no goroutine, no buffer.
var Noop Recorder = noopRecorder{}
