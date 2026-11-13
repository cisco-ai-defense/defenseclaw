// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// completionStreamGuard releases a streamed completion to the client only
// after the guardrail has checked it (rel-1-0-10:GAP-0212). The proxy used to
// check the accumulated text every 500 bytes and forward the chunks in
// between at once, so up to 499 bytes after each check, and the whole tail
// after the last one, reached the client unchecked; the final check of the
// whole text ran after the stream had been delivered and could not stop it.
//
// The guard holds every output unit (an SSE frame, a line or a marshalled
// chunk) until the text it carries has been checked, and checks again before
// it releases anything:
//
//   - Every check covers all text not yet released plus the last
//     streamGuardOverlap bytes before it, so a match split across chunks, or
//     one that needs context the client already has, is still found.
//   - After a clean check the guard keeps back the text that may still turn
//     into a match when more arrives: the last streamGuardHoldback bytes, the
//     whitespace-free run at the end (a token is never sent in part) and an
//     open private-key PEM block. So a secret's first bytes are not sent
//     before the bytes that complete it have been checked.
//   - Finish checks the whole remaining tail and releases it only when it is
//     clean, so the end of a stream is enforced like its middle.
//
// A guard with no check (a mode that does not enforce) releases every unit at
// once. The guard is used by one goroutine.
type completionStreamGuard struct {
	check     func(window string) *ScanVerdict
	scanEvery int

	text        strings.Builder
	units       []streamGuardUnit
	checkedEnd  int // text[:checkedEnd] was covered by a clean check
	releasedEnd int // text[:releasedEnd] has been released
	scans       int
	blocked     *ScanVerdict
}

type streamGuardUnit struct {
	data    []byte
	textEnd int // the unit carries text up to this offset
}

const (
	// streamGuardScanEvery is the default amount of new text the guard collects
	// before it checks (guardrail.stream_buffer_bytes overrides it).
	streamGuardScanEvery = 256
	// streamGuardOverlap is how much already released text a check rescans.
	// It is longer than any bounded content rule match (the bulk JSON PII rule
	// spans at most about 1.6 KiB); a private-key block is held open instead.
	streamGuardOverlap = 4096
	// streamGuardHoldback is text kept back after a clean check, enough for a
	// spaced card number or a labelled value whose end has not arrived.
	streamGuardHoldback = 64
	// streamGuardMaxRun bounds the whitespace-free run kept back, so a long
	// base64 blob still streams (it has been checked; only its end is held).
	streamGuardMaxRun = 8 << 10
)

func newCompletionStreamGuard(check func(window string) *ScanVerdict, scanEvery int) *completionStreamGuard {
	if scanEvery <= 0 {
		scanEvery = streamGuardScanEvery
	}
	return &completionStreamGuard{check: check, scanEvery: scanEvery}
}

// Push adds text the model produced and the output unit that carries it (nil
// when the caller releases that output itself, such as a buffered tool-call
// chunk). It returns the units that may be sent now, in order, or the
// blocking verdict; after a block nothing more is released.
func (g *completionStreamGuard) Push(text string, data []byte) ([][]byte, *ScanVerdict) {
	if g.blocked != nil {
		return nil, g.blocked
	}
	g.text.WriteString(text)
	if data != nil {
		g.units = append(g.units, streamGuardUnit{data: data, textEnd: g.text.Len()})
	}
	if g.check == nil {
		return g.release(g.text.Len()), nil
	}
	if g.text.Len()-g.checkedEnd >= g.scanEvery {
		if v := g.runCheck(); v != nil {
			return nil, v
		}
	}
	return g.release(g.safeEnd()), nil
}

// Finish checks the whole text not yet released and returns every held unit
// when it is clean, or the blocking verdict.
func (g *completionStreamGuard) Finish() ([][]byte, *ScanVerdict) {
	if g.blocked != nil {
		return nil, g.blocked
	}
	if g.check != nil && g.text.Len() > g.releasedEnd {
		if v := g.runCheck(); v != nil {
			return nil, v
		}
	}
	return g.release(g.text.Len()), nil
}

// Text is everything the model produced so far.
func (g *completionStreamGuard) Text() string { return g.text.String() }

// Scans is the number of checks run.
func (g *completionStreamGuard) Scans() int { return g.scans }

// Held is the number of text bytes produced but not yet released.
func (g *completionStreamGuard) Held() int { return g.text.Len() - g.releasedEnd }

func (g *completionStreamGuard) runCheck() *ScanVerdict {
	text := g.text.String()
	start := g.releasedEnd - streamGuardOverlap
	if open := secretshape.OpenPrivateKeyPEMStart(text); open >= 0 && open < start {
		start = open
	}
	if start <= 0 {
		start = 0
	} else if nl := strings.LastIndexByte(text[:start], '\n'); nl >= 0 && start-nl <= streamGuardOverlap {
		// Start on a line so a rule anchored at a line start reads the window
		// as it reads the whole text.
		start = nl + 1
	} else {
		for start < len(text) && !utf8.RuneStart(text[start]) {
			start++
		}
	}
	g.scans++
	v := g.check(text[start:])
	if v != nil && v.Severity != "NONE" && v.Action == guardrailActionBlock {
		g.blocked = v
		g.units = nil
		return v
	}
	g.checkedEnd = len(text)
	return nil
}

// safeEnd is the end of the text a clean check allows to release.
func (g *completionStreamGuard) safeEnd() int {
	text := g.text.String()
	end := g.checkedEnd - streamGuardHoldback
	if run := trailingRunStart(text[:g.checkedEnd]); run < end {
		end = run
	}
	if open := secretshape.OpenPrivateKeyPEMStart(text[:g.checkedEnd]); open >= 0 && open < end {
		end = open
	}
	if end < g.releasedEnd {
		end = g.releasedEnd
	}
	return end
}

// trailingRunStart is where the whitespace-free run at the end of text
// starts, at most streamGuardMaxRun bytes back.
func trailingRunStart(text string) int {
	floor := len(text) - streamGuardMaxRun
	if floor < 0 {
		floor = 0
	}
	i := len(text)
	for i > floor {
		r, size := utf8.DecodeLastRuneInString(text[:i])
		if unicode.IsSpace(r) {
			return i
		}
		i -= size
	}
	return i
}

func (g *completionStreamGuard) release(end int) [][]byte {
	n := 0
	for n < len(g.units) && g.units[n].textEnd <= end {
		n++
	}
	if n == 0 {
		return nil
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = g.units[i].data
	}
	if last := g.units[n-1].textEnd; last > g.releasedEnd {
		g.releasedEnd = last
	}
	g.units = append(g.units[:0], g.units[n:]...)
	return out
}

// streamGuardCheck is the enforced check a proxy stream runs on each guard
// window: the regex-only mid-stream inspection, with a confirm verdict
// resolved as for any completion. Nil (release at once) unless mode is action.
func (p *GuardrailProxy) streamGuardCheck(ctx context.Context, r *http.Request, model, mode string) func(string) *ScanVerdict {
	if mode != "action" {
		return nil
	}
	return func(window string) *ScanVerdict {
		verdict := p.inspector.InspectMidStream(ctx, "completion", window,
			[]ChatMessage{{Role: "assistant", Content: window}}, model, mode)
		p.resolveConfirm(r.Context(), r, verdict, "completion", model, mode)
		return verdict
	}
}

// streamGuardScanEvery is guardrail.stream_buffer_bytes: how much new text a
// stream collects before it is checked and released.
func (p *GuardrailProxy) streamGuardScanEvery() int {
	if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
		return p.cfg.StreamBufferBytes
	}
	return streamGuardScanEvery
}

// writeStreamUnits sends released units and flushes once.
func writeStreamUnits(w http.ResponseWriter, flusher http.Flusher, units [][]byte) {
	if len(units) == 0 {
		return
	}
	for _, unit := range units {
		_, _ = w.Write(unit)
	}
	if flusher != nil {
		flusher.Flush()
	}
}
