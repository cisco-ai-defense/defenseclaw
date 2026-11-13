// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

// S1 call sites of the S10 usage record (streams/S1/USAGE-INTERFACE.md v1):
// one Call per forwarded upstream call, fed with the response bytes the
// agent receives, ended exactly once. With tokenomics off the engine
// returns a no-op Call, so the only cost is one interface call per request.

const usageBodyCap = 10 << 20

// usageRecorder is the process usage engine (S10) while tokenomics is on,
// else the no-op recorder (no wrapper, no response copy: off is free).
func usageRecorder() modelusage.Recorder {
	if e := processModelUsage.Load(); e != nil && e.Enabled() {
		return e
	}
	return modelusage.Noop
}

// usageOn reports whether usage records are kept at all.
func usageOn() bool { return usageRecorder() != modelusage.Noop }

// usageAPIFamily maps a request path to the usage API family.
func usageAPIFamily(path string) modelusage.APIFamily {
	if f := passthroughAPIFamily(path); f != "" {
		return modelusage.APIFamily(f)
	}
	p := strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(p, "/chat/completions"):
		return modelusage.FamilyChat
	case p == "/responses" || strings.HasSuffix(p, "/responses"):
		return modelusage.FamilyResponses
	case strings.Contains(p, ":generateContent") || strings.Contains(p, ":streamGenerateContent"):
		return modelusage.FamilyGemini
	case strings.HasSuffix(p, "/api/generate") || strings.HasSuffix(p, "/api/chat"):
		return modelusage.FamilyOllama
	}
	return modelusage.FamilyOther
}

// usageRouteFacts copies the routing facts of an outcome.
func usageRouteFacts(o SemanticRouteOutcome, routerOn bool) modelusage.RouteFacts {
	if !routerOn {
		return modelusage.RouteFacts{Decision: modelusage.DecisionNone}
	}
	rf := modelusage.RouteFacts{Decision: o.Result, FallbackReason: o.FailureCode, RouteLatency: o.Latency, Confidence: -1}
	if d := o.Route; d != nil {
		rf.Source, rf.Category, rf.RuleID, rf.FilteredBy = d.Source, d.Category, d.RuleID, d.FilteredBy
		rf.Confidence, rf.CandidateAlias = d.Confidence, d.Candidate
		if d.Backend != nil {
			rf.SelectedAlias = d.Backend.Alias
		}
	}
	if rf.Decision == "" {
		rf.Decision = modelusage.DecisionFallback
	}
	return rf
}

// usageIdentity fills the verified caller and the privacy-safe profile
// label; X-User-Id and other headers never fill Subject.
func usageIdentity(ctx context.Context, f *modelusage.CallFacts) {
	if s, ok := verifiedSubjectFromContext(ctx); ok {
		f.Subject, f.SubjectKind, f.IdentityVerified = s.UserID, s.Source, true
	}
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil && f.IdentityVerified {
		f.ProfileName, f.ProfileDigest = resolved.decision.Name, resolved.decision.Digest
	}
}

// usageResponseWriter feeds the response bytes to a usage Call.
type usageResponseWriter struct {
	http.ResponseWriter
	call      modelusage.Call
	streaming bool

	mu     sync.Mutex
	header bool
	body   []byte
	over   bool
	ended  bool
}

func (u *usageResponseWriter) WriteHeader(status int) {
	u.mu.Lock()
	if !u.header {
		u.header = true
		u.call.UpstreamHeader(status, u.Header())
	}
	u.mu.Unlock()
	u.ResponseWriter.WriteHeader(status)
}

func (u *usageResponseWriter) Write(p []byte) (int, error) {
	u.mu.Lock()
	if !u.header {
		u.header = true
		u.call.UpstreamHeader(http.StatusOK, u.Header())
	}
	if u.streaming {
		u.call.Chunk(p)
	} else if !u.over {
		if len(u.body)+len(p) > usageBodyCap {
			u.over, u.body = true, nil
		} else {
			u.body = append(u.body, p...)
		}
	}
	u.mu.Unlock()
	return u.ResponseWriter.Write(p)
}

func (u *usageResponseWriter) Flush() {
	if f, ok := u.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (u *usageResponseWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func (u *usageResponseWriter) end(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ended {
		return
	}
	u.ended = true
	if !u.streaming && len(u.body) > 0 {
		u.call.Body(u.body)
	}
	u.body = nil
	u.call.End(err)
}

// beginUsage starts the usage record of one forwarded call and returns the
// writer to answer through and the function that ends the record.
func beginUsage(ctx context.Context, w http.ResponseWriter, f modelusage.CallFacts) (http.ResponseWriter, func(error)) {
	if !usageOn() {
		return w, func(error) {}
	}
	if f.StartedAt.IsZero() {
		f.StartedAt = time.Now()
	}
	usageIdentity(ctx, &f)
	if f.RequestID == "" {
		f.RequestID = RequestIDFromContext(ctx)
	}
	uw := &usageResponseWriter{ResponseWriter: w, call: usageRecorder().Begin(ctx, f), streaming: f.Streaming}
	return uw, uw.end
}

// streamingPath reports a path that streams whatever the body says:
// Bedrock converse-stream / invoke-with-response-stream and Gemini
// streamGenerateContent.
func streamingPath(path string) bool {
	if strings.Contains(path, ":streamGenerateContent") {
		return true
	}
	switch bedrockActionFromPath(path) {
	case "converse-stream", "invoke-with-response-stream":
		return true
	}
	return false
}

// usageStreaming decides whether a request streams: the path, the body
// stream flag, and Ollama, which streams unless stream is false.
func usageStreaming(path string, body []byte, bodyStream bool) bool {
	if streamingPath(path) || bodyStream {
		return true
	}
	p := strings.TrimRight(path, "/")
	if strings.HasSuffix(p, "/api/generate") || strings.HasSuffix(p, "/api/chat") {
		var probe struct {
			Stream *bool `json:"stream"`
		}
		_ = json.Unmarshal(body, &probe)
		return probe.Stream == nil || *probe.Stream
	}
	return false
}

// usageDecision is the record decision of a forwarded call: applied only
// when the call went to the routed backend.
func usageDecision(rf modelusage.RouteFacts, routed bool) modelusage.RouteFacts {
	if rf.Decision == modelusage.DecisionApplied && !routed {
		rf.Decision = modelusage.DecisionFallback
		if rf.FallbackReason == "" || rf.FallbackReason == SemanticRouteFailureNone {
			rf.FallbackReason = SemanticRouteFailureFiltered
		}
	}
	return rf
}

// includeUsageKey is set on a request context when the gateway added
// stream_options.include_usage, so the usage-only chunk is not forwarded to
// a client that never asked for it.
type includeUsageKey struct{}

// withStreamIncludeUsage adds stream_options.include_usage to a streamed
// chat body when usage records are on and the client did not ask for it
// (USAGE-INTERFACE v1). It returns the body and whether it added the flag.
func withStreamIncludeUsage(body []byte) ([]byte, bool) {
	if !usageOn() || len(body) == 0 {
		return body, false
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil || raw == nil {
		return body, false
	}
	var stream bool
	if json.Unmarshal(raw["stream"], &stream) != nil || !stream {
		return body, false
	}
	opts := map[string]json.RawMessage{}
	if prior, ok := raw["stream_options"]; ok {
		if json.Unmarshal(prior, &opts) != nil {
			return body, false
		}
		var include bool
		if json.Unmarshal(opts["include_usage"], &include) == nil && include {
			return body, false
		}
	}
	opts["include_usage"] = json.RawMessage("true")
	encoded, err := json.Marshal(opts)
	if err != nil {
		return body, false
	}
	raw["stream_options"] = encoded
	out, err := json.Marshal(raw)
	if err != nil {
		return body, false
	}
	return out, true
}

// isUsageOnlyChunk reports an SSE data payload that carries only usage (an
// empty choices list), the chunk include_usage adds at the end.
func isUsageOnlyChunk(payload string) bool {
	var c struct {
		Choices []json.RawMessage `json:"choices"`
		Usage   json.RawMessage   `json:"usage"`
	}
	if json.Unmarshal([]byte(payload), &c) != nil {
		return false
	}
	return len(c.Choices) == 0 && len(c.Usage) > 0 && string(c.Usage) != "null"
}

// recordChatUsage hands usage the proxy already parsed (Bifrost) to the
// record of the call answering through w.
func recordChatUsage(w http.ResponseWriter, u *ChatUsage) {
	uw, ok := w.(*usageResponseWriter)
	if !ok || u == nil {
		return
	}
	uw.call.Usage(modelusage.ParsedUsage{Input: u.PromptTokens, Output: u.CompletionTokens, Source: "provider"})
}
