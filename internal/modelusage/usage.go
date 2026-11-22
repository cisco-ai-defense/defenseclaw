// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package modelusage records what every model call cost: tokens, routing
// provenance, price-table cost and latency. The proxy and the connectors call
// it through Recorder; it owns the parsers, the cost engine and every sink.
// It imports nothing from internal/gateway.
package modelusage

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
)

// maxCount bounds every token count a provider may report. 2^53 keeps the
// value exactly representable in the float64 metric and JSON paths.
const maxCount = int64(1) << 53

// APIFamily names the wire API of one model call.
type APIFamily string

const (
	FamilyChat      APIFamily = "chat"
	FamilyMessages  APIFamily = "messages"
	FamilyResponses APIFamily = "responses"
	FamilyConverse  APIFamily = "converse"
	FamilyInvoke    APIFamily = "invoke"
	FamilyGemini    APIFamily = "gemini"
	FamilyOllama    APIFamily = "ollama"
	FamilyOther     APIFamily = "other"
)

// Has says which token counts a Usage carries. A zero count with its bit set
// is a real zero; a clear bit is an absent count. Absent never becomes 0.
type Has uint8

const (
	HasInput Has = 1 << iota
	HasOutput
	HasCacheRead
	HasCacheCreation
	HasReasoning
)

// Usage source values.
const (
	SourceProvider    = "provider"     // a non-stream response body
	SourceStreamFinal = "stream_final" // the usage block at the end of a stream
	SourceHeader      = "header"       // provider response headers (Bedrock invoke)
	SourceNativeOTel  = "native_otel"  // imported from an agent OTLP stream
)

// Usage is the canonical token accounting of one model call.
//
// Input is every prompt token billed, cached ones included (the OpenTelemetry
// gen_ai.usage.input_tokens meaning); CacheRead and CacheCreation are subsets
// of Input. Output is every completion token billed, reasoning included;
// Reasoning is a subset of Output. Parsers normalise each provider to this.
type Usage struct {
	Input         int64
	Output        int64
	CacheRead     int64
	CacheCreation int64
	Reasoning     int64
	Has           Has
	ResponseModel string
	Source        string
	// Anomaly is set when the provider numbers disagreed (a cache subset larger
	// than the input, a negative or absurd count). The offending counts are
	// dropped, never clamped.
	Anomaly string
	// Partial names a billing feature the flat price table cannot price
	// (service tier, 1h cache writes, server tools, long context). The cost
	// engine marks such a cost partial instead of silently under-pricing it.
	Partial string
}

// IsEmpty reports whether the usage carries no count at all.
func (u Usage) IsEmpty() bool { return u.Has == 0 }

func (u *Usage) set(h Has, dst *int64, v optInt) {
	if !v.ok {
		return
	}
	if v.v < 0 || v.v > maxCount {
		u.Anomaly = "invalid_count"
		return
	}
	*dst = v.v
	u.Has |= h
}

// seal drops cache subsets that exceed their parent total.
func (u *Usage) seal() {
	if u.Has&HasInput != 0 && u.Has&(HasCacheRead|HasCacheCreation) != 0 {
		sub := int64(0)
		if u.Has&HasCacheRead != 0 {
			sub += u.CacheRead
		}
		if u.Has&HasCacheCreation != 0 {
			sub += u.CacheCreation
		}
		if sub > u.Input {
			u.CacheRead, u.CacheCreation = 0, 0
			u.Has &^= HasCacheRead | HasCacheCreation
			u.Anomaly = "inconsistent_cache"
		}
	}
	if u.Has&HasOutput != 0 && u.Has&HasReasoning != 0 && u.Reasoning > u.Output {
		u.Reasoning = 0
		u.Has &^= HasReasoning
		u.Anomaly = "inconsistent_reasoning"
	}
}

// optInt is an optional JSON integer. It tolerates integral floats and null.
type optInt struct {
	v  int64
	ok bool
}

func (o *optInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	if n, err := strconv.ParseInt(string(b), 10, 64); err == nil {
		o.v, o.ok = n, true
		return nil
	}
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return nil // a non-number is absent, not an error that loses the block
	}
	if f == math.Trunc(f) && !math.IsInf(f, 0) && !math.IsNaN(f) && math.Abs(f) <= float64(maxCount) {
		o.v, o.ok = int64(f), true
	}
	return nil
}

func addOpt(a, b optInt) optInt {
	switch {
	case a.ok && b.ok:
		return optInt{v: a.v + b.v, ok: true}
	case a.ok:
		return a
	default:
		return b
	}
}
