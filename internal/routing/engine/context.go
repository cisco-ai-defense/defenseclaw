// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// ClassifierTextLimit bounds the text a classifier sees: the newest user
// turn, or the routing.context text for a classifier that reads text.
const ClassifierTextLimit = 8 << 10

// Tool-name bounds of routing.context.include_tool_names.
const (
	ContextMaxToolNames  = 32
	ContextToolNameBytes = 64
)

// contextSeparator joins turns with a line break on both sides, so the end
// of one turn and the start of the next never read as one word.
const contextSeparator = "\n\n"

// contextToolsPrefix starts the signal-only tool-name line.
const contextToolsPrefix = "tools: "

// ContextOptions is routing.context compiled for one generation.
type ContextOptions struct {
	RecentTurns  int
	FirstTurn    bool
	MaxBytes     int
	PerTurnBytes int
	ToolNames    bool
}

// contextOptionsOf compiles routing.context; vllm_sr (which validation
// refuses with an active context) classifies the newest turn only.
func contextOptionsOf(r config.RoutingConfig) ContextOptions {
	c := r.Context
	if !c.Active() || r.EffectiveClassifier() == config.RoutingClassifierVLLMSR {
		return ContextOptions{}
	}
	return ContextOptions{
		RecentTurns: c.RecentUserTurns, FirstTurn: c.IncludeFirstUserTurn,
		MaxBytes: c.EffectiveMaxBytes(), PerTurnBytes: c.EffectivePerTurnBytes(), ToolNames: c.IncludeToolNames,
	}
}

// Active reports whether the options read more than the newest turn.
func (o ContextOptions) Active() bool { return o.RecentTurns > 0 || o.FirstTurn || o.ToolNames }

// classifierText returns the classifier text, the keyword signals and the
// truncation warning of req. With routing.context off, or nothing beyond
// the newest turn, it is the 1.0.9 answer: req.Text and its signals. With
// context, the signals of req.Text are kept and the context signals are
// added, so the context and its caps never take a signal away.
func (e *Engine) classifierText(req Request) (string, map[string]bool, string) {
	signals := e.matcher.Match(req.Text)
	o := e.context
	older, first, tools := req.ContextTurns, req.FirstTurn, req.ToolNames
	if len(older) > o.RecentTurns {
		older = older[:o.RecentTurns]
	}
	if !o.FirstTurn {
		first = ""
	}
	if !o.ToolNames {
		tools = nil
	}
	if !o.Active() || (len(older) == 0 && first == "" && len(tools) == 0) {
		return req.Text, signals, ""
	}
	text, signalText, caps := assembleContext(req.Text, older, first, tools, o)
	for name := range e.matcher.Match(signalText) {
		if signals == nil {
			signals = map[string]bool{}
		}
		signals[name] = true
	}
	if len(text) > ClassifierTextLimit {
		text = cutUTF8(text, ClassifierTextLimit)
		if e.classifierName() != SourceRules {
			caps = caps.Union(bounded.Of(bounded.Bytes))
		}
	}
	if !caps.Any() {
		return text, signals, ""
	}
	return text, signals, contextWarning(caps)
}

// assembleContext builds the context text: the newest turn, the older turns
// newest first, then the first turn, joined by contextSeparator, each cut
// at PerTurnBytes and the whole at MaxBytes on a UTF-8 boundary. The newest
// turn is never dropped (it is cut, alone, at the per-turn cap); what is
// left of MaxBytes goes to the older turns. tools become the signal-only
// line "tools: a,b" (at most ContextMaxToolNames names, each cut at
// ContextToolNameBytes). signal is text plus that line, and text is a
// prefix of it. caps names every cap hit: Bytes for cut or dropped text,
// Items for dropped tool names. What was read before a cap is kept.
func assembleContext(newest string, older []string, first string, tools []string, o ContextOptions) (text, signal string, caps bounded.CapSet) {
	var t bounded.Truncated
	var b strings.Builder
	per := min(o.PerTurnBytes, o.MaxBytes)
	add := func(s string, room int) {
		cut := cutUTF8(s, min(per, room))
		if len(cut) < len(s) {
			t.Hit(bounded.Bytes)
		}
		b.WriteString(cut)
	}
	add(newest, o.MaxBytes)
	turns := older
	if first != "" {
		turns = append(slices.Clip(older), first)
	}
	for _, s := range turns {
		room := o.MaxBytes - b.Len() - len(contextSeparator)
		if room <= 0 {
			t.Hit(bounded.Bytes)
			break
		}
		b.WriteString(contextSeparator)
		add(s, room)
	}
	textLen := b.Len()
	if len(tools) > 0 {
		if len(tools) > ContextMaxToolNames {
			t.Hit(bounded.Items)
			tools = tools[:ContextMaxToolNames]
		}
		b.WriteString(contextSeparator)
		b.WriteString(contextToolsPrefix)
		for i, name := range tools {
			if i > 0 {
				b.WriteByte(0x2c) // ,
			}
			cut := cutUTF8(name, ContextToolNameBytes)
			if len(cut) < len(name) {
				t.Hit(bounded.Bytes)
			}
			b.WriteString(cut)
		}
	}
	signal = b.String()
	return signal[:textLen], signal, t.Set()
}

// contextWarning is the Decision.Warnings entry of a truncated context:
// "context_truncated:bytes,items".
func contextWarning(caps bounded.CapSet) string {
	const prefix = "context_truncated:"
	var b strings.Builder
	b.WriteString(prefix)
	for _, c := range bounded.Caps() {
		if caps.Has(c) {
			if b.Len() > len(prefix) {
				b.WriteByte(0x2c)
			}
			b.WriteString(c.String())
		}
	}
	return b.String()
}

// cutUTF8 returns at most n bytes of s, cut on a rune boundary.
func cutUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
