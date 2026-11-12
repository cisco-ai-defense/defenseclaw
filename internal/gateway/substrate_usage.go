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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/usage"
)

// SubstrateModelMeter meters the model calls of actors: the seam where
// stream 10 (tokenomics) plugs in (PLAN D6). The shape is the stream 1
// and 10 usage interface (internal/modelusage Recorder and Call, see the
// 1.0.10 S1 USAGE-INTERFACE): Begin once per forwarded call after the
// route is final and before the upstream request; UpstreamHeader at the
// first response byte; Chunk with the bytes exactly as written to the
// actor (no retention by the caller); End exactly once. Implementations
// must not block the response path.
type SubstrateModelMeter interface {
	Begin(ctx context.Context, call SubstrateModelCall) SubstrateMeteredCall
}

// SubstrateMeteredCall is one metered model call.
type SubstrateMeteredCall interface {
	UpstreamHeader(status int, h http.Header)
	Chunk(p []byte)
	End(err error)
}

// SubstrateModelCall is what a meter knows of a call before it is sent:
// the verified caller (never a header), the requested and the routed
// route, and the route decision.
type SubstrateModelCall struct {
	RequestID string
	Caller    SubstrateModelCaller
	Requested SubstrateLLMRoute
	Selected  SubstrateLLMRoute
	// Route is none (no router), kept or narrowed.
	Route     string
	API       string
	Streaming bool
	StartedAt time.Time
}

// substrateMeterWriter feeds a metered call what the proxy writes to the
// actor. It keeps Flush and Unwrap so streaming is unchanged.
type substrateMeterWriter struct {
	http.ResponseWriter
	call   SubstrateMeteredCall
	status int
	sent   bool
}

func (m *substrateMeterWriter) header() {
	if !m.sent {
		m.sent = true
		if m.status == 0 {
			m.status = http.StatusOK
		}
		m.call.UpstreamHeader(m.status, m.ResponseWriter.Header())
	}
}

func (m *substrateMeterWriter) WriteHeader(status int) {
	if !m.sent && status >= 200 {
		m.status = status
		m.header()
	}
	m.ResponseWriter.WriteHeader(status)
}

func (m *substrateMeterWriter) Write(p []byte) (int, error) {
	m.header()
	n, err := m.ResponseWriter.Write(p)
	if n > 0 {
		m.call.Chunk(p[:n])
	}
	return n, err
}

func (m *substrateMeterWriter) Flush() {
	m.header()
	_ = http.NewResponseController(m.ResponseWriter).Flush()
}

func (m *substrateMeterWriter) Unwrap() http.ResponseWriter { return m.ResponseWriter }

// SubstrateBudgets are the token budgets of substrate.budgets: when a
// batch's or an atespace's tokens reach the limit, the gateway warns once
// (audit, log, metric, the batch view). Zero is off. Downgrade and deny
// are stream 10 (on_exceed); here a budget only warns.
type SubstrateBudgets struct {
	BatchTokens    int64
	AtespaceTokens int64
}

// SubstrateUsageMeterConfig configures the gateway's own meter.
type SubstrateUsageMeterConfig struct {
	// Store receives the records (usage.Remote on a gateway replica).
	Store   usage.Store
	Budgets SubstrateBudgets
	// OnRecord sees every record (metrics: no identity labels).
	OnRecord func(r usage.Record)
	// OnBudgetWarn sees every budget warning.
	OnBudgetWarn func(scope string)
	// OnDrop counts records not stored.
	OnDrop func(n int, reason string)
}

// SubstrateUsageMeter is the interim meter (until stream 10): it reads the
// provider's own usage from the response (headers, JSON body, SSE or AWS
// eventstream), writes one usage.Record per call to the leader and warns
// on budgets.
type SubstrateUsageMeter struct {
	cfg    SubstrateUsageMeterConfig
	logger *audit.Logger
	writer *usage.Writer
}

// NewSubstrateUsageMeter returns the meter; its budget warnings go to the
// API server's audit log.
func NewSubstrateUsageMeter(api *APIServer, cfg SubstrateUsageMeterConfig) *SubstrateUsageMeter {
	m := &SubstrateUsageMeter{cfg: cfg}
	if api != nil {
		m.logger = api.logger
	}
	m.writer = &usage.Writer{Store: cfg.Store, OnResult: m.checkBudgets, OnDrop: func(n int, reason string) {
		fmt.Fprintf(os.Stderr, "[substrate] usage: %d record(s) not stored (%s)\n", n, reason)
		if cfg.OnDrop != nil {
			cfg.OnDrop(n, reason)
		}
	}}
	return m
}

// Close sends what is queued (tests and shutdown).
func (m *SubstrateUsageMeter) Close() { m.writer.Close() }

// Begin implements SubstrateModelMeter.
func (m *SubstrateUsageMeter) Begin(_ context.Context, c SubstrateModelCall) SubstrateMeteredCall {
	return &substrateMetered{m: m, c: c, p: newSubstrateUsageParser(c)}
}

type substrateMetered struct {
	m      *SubstrateUsageMeter
	c      SubstrateModelCall
	p      *substrateUsageParser
	status int
	once   sync.Once
}

func (c *substrateMetered) UpstreamHeader(status int, h http.Header) {
	c.status = status
	c.p.header(h)
}

func (c *substrateMetered) Chunk(p []byte) { c.p.chunk(p) }

func (c *substrateMetered) End(err error) {
	c.once.Do(func() {
		tok, model, src := c.p.result()
		if c.c.RequestID == "" {
			return
		}
		requested := c.c.Requested.Model
		if model == "" {
			model = c.c.Selected.Model
		}
		r := usage.Record{
			RequestID: c.c.RequestID, At: c.c.StartedAt.UTC(),
			OwnerID: c.c.Caller.Owner, Principal: c.c.Caller.Principal, OwnerKind: c.c.Caller.Kind,
			Atespace: c.c.Caller.Atespace, Actor: c.c.Caller.Name, ActorUID: c.c.Caller.UID,
			Template: c.c.Caller.Template, BatchID: c.c.Caller.BatchID, Profile: c.c.Caller.Profile,
			Connector: c.c.Caller.Connector, Unattended: c.c.Caller.Unattended,
			Provider: c.c.Selected.Provider, API: c.c.API, RequestedModel: requested, Model: model,
			Route: c.c.Route, Status: c.status, Streaming: c.c.Streaming,
			Tokens: tok, UsageSource: src, DurationMS: time.Since(c.c.StartedAt).Milliseconds(),
		}
		if err != nil && r.Status == 0 {
			r.Status = http.StatusBadGateway
		}
		// One line per call for the operator: no person, prompt or key;
		// the owner is a short digest so lines can be grouped.
		fmt.Fprintf(os.Stderr, "[substrate] model usage request=%s atespace=%s actor=%s actor_uid=%s owner=%s batch=%s provider=%s model=%s route=%s status=%d input=%d output=%d cache_read=%d cache_write=%d source=%s\n",
			r.RequestID, r.Atespace, r.Actor, r.ActorUID, ownerDigest(r.OwnerID), r.BatchID, r.Provider,
			substrateLogToken(r.Model), r.Route, r.Status, r.Input, r.Output, r.CacheRead, r.CacheCreation, r.UsageSource)
		if c.m.cfg.OnRecord != nil {
			c.m.cfg.OnRecord(r)
		}
		c.m.writer.Add(r)
	})
}

// ownerDigest is a short, stable, non-reversible tag of an owner ID.
func ownerDigest(id string) string {
	if id == "" {
		return "-"
	}
	s := sha256.Sum256([]byte(id))
	return hex.EncodeToString(s[:6])
}

// substrateLogToken keeps a log value to model-id characters.
func substrateLogToken(s string) string {
	if s == "" {
		return "-"
	}
	b := []byte(s)
	if len(b) > 128 {
		b = b[:128]
	}
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".-_:@/", c) >= 0) {
			b[i] = '_'
		}
	}
	return string(b)
}

// checkBudgets warns once when an append takes a scope to its limit.
func (m *SubstrateUsageMeter) checkBudgets(res usage.AppendResult) {
	for _, sc := range res.Scopes {
		limit := m.limit(sc.Scope)
		if limit <= 0 || sc.Before >= limit || sc.After < limit {
			continue
		}
		target := "substrate-budget:" + sc.Scope + "/" + sc.ID
		details := fmt.Sprintf("scope=%s id=%s atespace=%s owner=%s limit_tokens=%d spent_tokens=%d on_exceed=warn",
			sc.Scope, sc.ID, sc.Atespace, ownerDigest(sc.OwnerID), limit, sc.After)
		fmt.Fprintf(os.Stderr, "[substrate] budget warning %s\n", details)
		if m.logger != nil {
			_ = m.logger.LogActionCtxSeverity(context.Background(), string(audit.ActionWarn), target, details, "WARN")
		}
		if m.cfg.OnBudgetWarn != nil {
			m.cfg.OnBudgetWarn(sc.Scope)
		}
	}
}

func (m *SubstrateUsageMeter) limit(scope string) int64 {
	switch scope {
	case usage.ScopeBatch:
		return m.cfg.Budgets.BatchTokens
	case usage.ScopeAtespace:
		return m.cfg.Budgets.AtespaceTokens
	}
	return 0
}

// The parsers read only usage fields; nothing else of a response is kept.
const (
	substrateUsageBodyCap  = 8 << 20  // a non-streaming body
	substrateUsageFrameCap = 16 << 20 // one eventstream message
	substrateUsageLineCap  = 4 << 20  // one SSE line
)

type substrateUsageParser struct {
	provider, api string
	streaming     bool
	kind          string // eventstream | sse | body

	buf    []byte
	broken bool

	tok     usage.Tokens
	model   string
	src     string
	have    bool
	metrics bool // Bedrock invocation metrics seen (authoritative)
}

func newSubstrateUsageParser(c SubstrateModelCall) *substrateUsageParser {
	return &substrateUsageParser{provider: c.Selected.Provider, api: c.API, streaming: c.Streaming}
}

func (p *substrateUsageParser) header(h http.Header) {
	ct := strings.ToLower(h.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/vnd.amazon.eventstream"):
		p.kind = "eventstream"
	case strings.Contains(ct, "text/event-stream"):
		p.kind = "sse"
	default:
		p.kind = "body"
	}
	if p.provider == "bedrock" {
		in, okIn := headerInt(h, "X-Amzn-Bedrock-Input-Token-Count")
		out, okOut := headerInt(h, "X-Amzn-Bedrock-Output-Token-Count")
		if okIn || okOut {
			p.tok.Input, p.tok.Output = in, out
			p.tok.CacheRead, _ = headerInt(h, "X-Amzn-Bedrock-Cache-Read-Input-Token-Count")
			p.tok.CacheCreation, _ = headerInt(h, "X-Amzn-Bedrock-Cache-Write-Input-Token-Count")
			p.src, p.have, p.metrics = usage.SourceHeader, true, true
		}
	}
}

func headerInt(h http.Header, k string) (int64, bool) {
	v := strings.TrimSpace(h.Get(k))
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}

func (p *substrateUsageParser) chunk(b []byte) {
	if p.broken {
		return
	}
	switch p.kind {
	case "eventstream":
		p.buf = append(p.buf, b...)
		p.drainEventstream()
	case "sse":
		p.buf = append(p.buf, b...)
		p.drainSSE(false)
	default:
		if len(p.buf)+len(b) > substrateUsageBodyCap {
			p.broken, p.buf = true, nil
			return
		}
		p.buf = append(p.buf, b...)
	}
}

func (p *substrateUsageParser) result() (usage.Tokens, string, string) {
	switch p.kind {
	case "sse":
		p.drainSSE(true)
	case "body", "":
		if !p.broken && len(p.buf) > 0 {
			p.observeJSON(p.buf, usage.SourceBody)
		}
	}
	p.buf = nil
	if !p.have {
		return usage.Tokens{}, p.model, usage.SourceAbsent
	}
	return p.tok, p.model, p.src
}

// drainEventstream decodes whole AWS eventstream messages (InvokeModel
// and Converse streams).
func (p *substrateUsageParser) drainEventstream() {
	dec := eventstream.NewDecoder()
	for len(p.buf) >= 12 {
		total := int(binary.BigEndian.Uint32(p.buf[:4]))
		if total < 16 || total > substrateUsageFrameCap {
			p.broken, p.buf = true, nil
			return
		}
		if len(p.buf) < total {
			return
		}
		msg, err := dec.Decode(bytes.NewReader(p.buf[:total]), nil)
		p.buf = p.buf[total:]
		if err != nil {
			p.broken, p.buf = true, nil
			return
		}
		var mtype, etype string
		for _, h := range msg.Headers {
			switch h.Name {
			case ":message-type":
				mtype = h.Value.String()
			case ":event-type":
				etype = h.Value.String()
			}
		}
		if mtype != "event" {
			continue
		}
		switch etype {
		case "chunk": // InvokeModelWithResponseStream: {"bytes":"<base64 provider event>"}
			var c struct {
				Bytes string `json:"bytes"`
			}
			if json.Unmarshal(msg.Payload, &c) != nil || c.Bytes == "" {
				continue
			}
			inner, err := base64.StdEncoding.DecodeString(c.Bytes)
			if err != nil {
				continue
			}
			p.observeJSON(inner, usage.SourceStream)
		case "metadata": // ConverseStream
			p.observeJSON(msg.Payload, usage.SourceStream)
		}
	}
	if len(p.buf) == 0 {
		p.buf = nil
	}
}

// drainSSE reads whole "data:" lines of a server-sent event stream.
func (p *substrateUsageParser) drainSSE(final bool) {
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			if len(p.buf) > substrateUsageLineCap {
				p.broken, p.buf = true, nil
			}
			if final && len(p.buf) > 0 {
				p.sseLine(p.buf)
				p.buf = nil
			}
			return
		}
		p.sseLine(p.buf[:i])
		p.buf = p.buf[i+1:]
	}
}

func (p *substrateUsageParser) sseLine(line []byte) {
	line = bytes.TrimRight(line, "\r")
	data, ok := bytes.CutPrefix(line, []byte("data:"))
	if !ok {
		return
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return
	}
	p.observeJSON(data, usage.SourceStream)
}

// substrateUsageEvent is the union of the usage fields of the provider
// APIs /llm serves (Anthropic Messages and its stream events, Bedrock
// invocation metrics and Converse, OpenAI chat and Responses, Gemini).
type substrateUsageEvent struct {
	Model   string `json:"model"`
	Type    string `json:"type"`
	Message *struct {
		Model string             `json:"model"`
		Usage *substrateRawUsage `json:"usage"`
	} `json:"message"`
	Usage    *substrateRawUsage `json:"usage"`
	Response *struct {
		Model string             `json:"model"`
		Usage *substrateRawUsage `json:"usage"`
	} `json:"response"`
	Metrics *struct {
		Input      *int64 `json:"inputTokenCount"`
		Output     *int64 `json:"outputTokenCount"`
		CacheRead  int64  `json:"cacheReadInputTokenCount"`
		CacheWrite int64  `json:"cacheWriteInputTokenCount"`
	} `json:"amazon-bedrock-invocationMetrics"`
	Gemini *struct {
		Prompt     *int64 `json:"promptTokenCount"`
		Candidates int64  `json:"candidatesTokenCount"`
		Thoughts   int64  `json:"thoughtsTokenCount"`
		Cached     int64  `json:"cachedContentTokenCount"`
	} `json:"usageMetadata"`
	ModelVersion string `json:"modelVersion"`
}

type substrateRawUsage struct {
	// Anthropic
	InputTokens   *int64 `json:"input_tokens"`
	OutputTokens  *int64 `json:"output_tokens"`
	CacheRead     int64  `json:"cache_read_input_tokens"`
	CacheCreation int64  `json:"cache_creation_input_tokens"`
	// OpenAI chat
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	PromptDetails    *struct {
		Cached int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	// OpenAI Responses
	InputDetails *struct {
		Cached int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	// Bedrock Converse
	ConverseIn         *int64 `json:"inputTokens"`
	ConverseOut        *int64 `json:"outputTokens"`
	ConverseCacheRead  int64  `json:"cacheReadInputTokens"`
	ConverseCacheWrite int64  `json:"cacheWriteInputTokens"`
}

// observeJSON merges one response object's usage. Within a stream each
// field takes its largest value (Anthropic splits input and output across
// message_start and message_delta); Bedrock invocation metrics, when
// present, are the provider's final count and win.
func (p *substrateUsageParser) observeJSON(b []byte, src string) {
	var e substrateUsageEvent
	if json.Unmarshal(b, &e) != nil {
		return
	}
	if p.model == "" {
		switch {
		case e.Message != nil && e.Message.Model != "":
			p.model = e.Message.Model
		case e.Response != nil && e.Response.Model != "":
			p.model = e.Response.Model
		case e.Model != "":
			p.model = e.Model
		case e.ModelVersion != "":
			p.model = e.ModelVersion
		}
	}
	if m := e.Metrics; m != nil && (m.Input != nil || m.Output != nil) {
		p.tok = usage.Tokens{Input: deref(m.Input), Output: deref(m.Output), CacheRead: m.CacheRead, CacheCreation: m.CacheWrite}
		p.src, p.have, p.metrics = src, true, true
		return
	}
	if p.metrics {
		return
	}
	var t usage.Tokens
	var ok bool
	u := e.Usage
	if u == nil && e.Message != nil {
		u = e.Message.Usage
	}
	if u == nil && e.Response != nil {
		u = e.Response.Usage
	}
	if u != nil {
		switch {
		case u.InputTokens != nil || u.OutputTokens != nil:
			t = usage.Tokens{Input: deref(u.InputTokens), Output: deref(u.OutputTokens), CacheRead: u.CacheRead, CacheCreation: u.CacheCreation}
			if u.InputDetails != nil && u.InputDetails.Cached > 0 && p.provider == "openai" {
				// Responses: input_tokens includes the cached part.
				t.CacheRead = u.InputDetails.Cached
				t.Input -= min(t.Input, u.InputDetails.Cached)
			}
			ok = true
		case u.PromptTokens != nil || u.CompletionTokens != nil:
			t = usage.Tokens{Input: deref(u.PromptTokens), Output: deref(u.CompletionTokens)}
			if u.PromptDetails != nil && u.PromptDetails.Cached > 0 {
				t.CacheRead = u.PromptDetails.Cached
				t.Input -= min(t.Input, u.PromptDetails.Cached)
			}
			ok = true
		case u.ConverseIn != nil || u.ConverseOut != nil:
			t = usage.Tokens{Input: deref(u.ConverseIn), Output: deref(u.ConverseOut), CacheRead: u.ConverseCacheRead, CacheCreation: u.ConverseCacheWrite}
			ok = true
		}
	} else if g := e.Gemini; g != nil && g.Prompt != nil {
		t = usage.Tokens{Input: *g.Prompt - min(*g.Prompt, g.Cached), Output: g.Candidates + g.Thoughts, CacheRead: g.Cached}
		ok = true
	}
	if !ok {
		return
	}
	p.tok.Input = max(p.tok.Input, t.Input)
	p.tok.Output = max(p.tok.Output, t.Output)
	p.tok.CacheRead = max(p.tok.CacheRead, t.CacheRead)
	p.tok.CacheCreation = max(p.tok.CacheCreation, t.CacheCreation)
	if !p.have || p.src == usage.SourceHeader {
		p.src = src
	}
	p.have = true
}

func deref(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// SubstrateUsageAPI answers the admin listener's usage route from the
// leader's store.
type SubstrateUsageAPI struct {
	Store usage.Store
}

// Usage implements SubstrateUsage.
func (u SubstrateUsageAPI) Usage(ctx context.Context, f usage.Filter) (usage.Summary, error) {
	return u.Store.Summary(ctx, f)
}

// BudgetSpent implements SubstrateUsage.
func (u SubstrateUsageAPI) BudgetSpent(ctx context.Context, q usage.ScopeQuery) (int64, error) {
	return u.Store.ScopeTotal(ctx, q)
}
