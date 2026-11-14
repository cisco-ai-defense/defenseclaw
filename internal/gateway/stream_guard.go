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

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
//   - Text is kept per lane: one lane per choice of an n>1 completion, so a
//     secret in one choice is not split by the tokens of another. A unit is
//     released when every lane has released the text pushed before it.
//   - Every local check covers all text not yet released plus the last
//     streamGuardOverlap bytes before it, so a match split across chunks, or
//     one that needs context the client already has, is still found. The
//     window never reaches back more than streamGuardOverlap plus
//     streamGuardMaxRun bytes before the new text, so the work per byte is
//     bounded.
//   - After a clean check the guard keeps back the text that may still turn
//     into a match when more arrives: the last streamGuardHoldback bytes, the
//     whitespace-free run at the end (at most streamGuardMaxRun bytes) and an
//     open private-key PEM block (at most the 64 KiB PEM bound). A block is
//     checked once from its header when its footer arrives; a block past the
//     bound is checked once as read and counts as truncated.
//   - The cloud lane (Cisco AI Defense in scanner mode remote or both) runs
//     every streamGuardCloudEvery bytes and at the end, not on every window.
//   - Finish checks the whole remaining tail, cloud lane included, and
//     releases it only when it is clean, so the end of a stream is enforced
//     like its middle.
//   - A cap a caller or the guard hits (an SSE line past its bound, a PEM
//     block past its bound) is recorded with the one bound rule
//     (internal/guardrail/bounded): limit decides whether the pack's unknown
//     tier blocks it; otherwise the stream goes on and Truncated reports it
//     for the final verdict.
//
// Bounds: a clean stream is held back by at most the larger of
// streamGuardHoldback plus the unchecked scan interval (text with spaces;
// about 340 bytes measured on prose), the whitespace-free run (8 KiB) or an
// open PEM block (64 KiB). A guard with no check (a mode that does not
// enforce) releases every unit at once. The guard is used by one goroutine.
type completionStreamGuard struct {
	check     func(window string) *ScanVerdict
	cloud     func(window string) *ScanVerdict
	limit     func(set bounded.CapSet) *ScanVerdict
	scanEvery int

	lanes     []*streamGuardLane
	laneIndex map[int]int
	units     []streamGuardUnit
	scans     int
	blocked   *ScanVerdict
	truncated bounded.Truncated
}

type streamGuardLane struct {
	text        strings.Builder
	checkedEnd  int // text[:checkedEnd] was covered by a clean check
	cloudEnd    int // text[:cloudEnd] was covered by a clean cloud check
	releasedEnd int // text[:releasedEnd] has been released
	pemStart    int // offset of an open private-key block, or -1
	pemScanned  int // text[:pemScanned] has been searched for a PEM header or footer
	pemFooter   int // offset of a candidate footer line of the open block, or -1
}

type streamGuardUnit struct {
	data []byte
	ends []int // per lane (in g.lanes order): the unit follows the text up to this offset
}

const (
	// streamGuardScanEvery is the default amount of new text the guard collects
	// before it checks (guardrail.stream_buffer_bytes overrides it).
	streamGuardScanEvery = 256
	// streamGuardOverlap is how much already checked text a check rescans.
	// It is longer than any bounded content rule match (the bulk JSON PII rule
	// spans at most about 1.6 KiB); a private-key block is held open instead.
	streamGuardOverlap = 4096
	// streamGuardHoldback is text kept back after a clean check, enough for a
	// spaced card number or a labelled value whose end has not arrived.
	streamGuardHoldback = 64
	// streamGuardMaxRun bounds the whitespace-free run kept back, so a long
	// base64 blob still streams (it has been checked; only its end is held).
	streamGuardMaxRun = 8 << 10
	// streamGuardCloudEvery is the new text between two cloud-lane checks.
	streamGuardCloudEvery = 4 << 10
	// streamGuardPEMBound is the PEM bound of secretshape: a block longer
	// than this is not a key the rules can validate.
	streamGuardPEMBound = 64 << 10
)

func newCompletionStreamGuard(check func(window string) *ScanVerdict, scanEvery int) *completionStreamGuard {
	if scanEvery <= 0 {
		scanEvery = streamGuardScanEvery
	}
	return &completionStreamGuard{check: check, scanEvery: scanEvery, laneIndex: map[int]int{}}
}

// withCloud sets the check of the cloud lane, run every
// streamGuardCloudEvery bytes and at Finish.
func (g *completionStreamGuard) withCloud(cloud func(window string) *ScanVerdict) *completionStreamGuard {
	g.cloud = cloud
	return g
}

// withLimit sets the verdict of a truncated stream: a blocking verdict when
// the pack's unknown tier blocks it, nil when it alerts.
func (g *completionStreamGuard) withLimit(limit func(set bounded.CapSet) *ScanVerdict) *completionStreamGuard {
	g.limit = limit
	return g
}

// Push adds text of lane 0 and the output unit that carries it.
func (g *completionStreamGuard) Push(text string, data []byte) ([][]byte, *ScanVerdict) {
	return g.PushLane(0, text, data)
}

// PushLane adds text the model produced for one lane (a choice index) and the
// output unit that carries it (nil when the caller releases that output
// itself, such as a buffered tool-call chunk). It returns the units that may
// be sent now, in order, or the blocking verdict; after a block nothing more
// is released.
func (g *completionStreamGuard) PushLane(lane int, text string, data []byte) ([][]byte, *ScanVerdict) {
	if g.blocked != nil {
		return nil, g.blocked
	}
	l := g.lane(lane)
	l.text.WriteString(text)
	if data != nil {
		ends := make([]int, len(g.lanes))
		for i, other := range g.lanes {
			ends[i] = other.text.Len()
		}
		g.units = append(g.units, streamGuardUnit{data: data, ends: ends})
	}
	if g.check == nil {
		for _, other := range g.lanes {
			other.releasedEnd = other.text.Len()
		}
		return g.release(), nil
	}
	if v := g.checkLane(l, false); v != nil {
		return nil, v
	}
	return g.release(), nil
}

// Truncate records that a cap cut the reading of the stream short (an SSE
// line past its bound). It returns the blocking verdict when the pack's
// unknown tier blocks a truncated input; then nothing more is released.
func (g *completionStreamGuard) Truncate(c bounded.Cap) *ScanVerdict {
	if g.blocked != nil {
		return g.blocked
	}
	g.truncated.Hit(c)
	if g.limit != nil {
		if v := g.limit(g.truncated.Set()); v != nil {
			g.blocked = v
			g.units = nil
			return v
		}
	}
	return nil
}

// Truncated is the set of caps the stream hit.
func (g *completionStreamGuard) Truncated() bounded.CapSet { return g.truncated.Set() }

// Finish checks every lane's text not yet released, cloud lane included, and
// returns every held unit when it is clean, or the blocking verdict.
func (g *completionStreamGuard) Finish() ([][]byte, *ScanVerdict) {
	if g.blocked != nil {
		return nil, g.blocked
	}
	if g.check != nil {
		for _, l := range g.lanes {
			if l.pemStart >= 0 {
				// The stream ended inside a block: check it from its header.
				if v := g.runCheck(l, l.pemStart, false); v != nil {
					return nil, v
				}
				l.pemStart = -1
			}
			if l.text.Len() > l.releasedEnd || l.text.Len() > l.checkedEnd {
				if v := g.runCheck(l, g.windowStart(l), false); v != nil {
					return nil, v
				}
			}
			if g.cloud != nil && l.text.Len() > l.cloudEnd {
				if v := g.runCheck(l, g.cloudStart(l), true); v != nil {
					return nil, v
				}
			}
			l.releasedEnd = l.text.Len()
		}
	} else {
		for _, l := range g.lanes {
			l.releasedEnd = l.text.Len()
		}
	}
	return g.releaseAll(), nil
}

// Text is everything the model produced so far: the lanes in the order they
// first carried text, separated by a blank line.
func (g *completionStreamGuard) Text() string {
	if len(g.lanes) == 1 {
		return g.lanes[0].text.String()
	}
	parts := make([]string, 0, len(g.lanes))
	for _, l := range g.lanes {
		if l.text.Len() > 0 {
			parts = append(parts, l.text.String())
		}
	}
	return strings.Join(parts, "\n\n")
}

// Scans is the number of checks run.
func (g *completionStreamGuard) Scans() int { return g.scans }

// Held is the number of text bytes produced but not yet released.
func (g *completionStreamGuard) Held() int {
	held := 0
	for _, l := range g.lanes {
		held += l.text.Len() - l.releasedEnd
	}
	return held
}

func (g *completionStreamGuard) lane(id int) *streamGuardLane {
	if i, ok := g.laneIndex[id]; ok {
		return g.lanes[i]
	}
	l := &streamGuardLane{pemStart: -1, pemFooter: -1}
	g.laneIndex[id] = len(g.lanes)
	g.lanes = append(g.lanes, l)
	return l
}

// checkLane runs the checks lane l is due for and moves its release mark.
func (g *completionStreamGuard) checkLane(l *streamGuardLane, final bool) *ScanVerdict {
	if v := g.trackPEM(l); v != nil {
		return v
	}
	if l.text.Len()-l.checkedEnd >= g.scanEvery || final {
		if v := g.runCheck(l, g.windowStart(l), false); v != nil {
			return v
		}
	}
	if g.cloud != nil && l.text.Len()-l.cloudEnd >= streamGuardCloudEvery {
		if v := g.runCheck(l, g.cloudStart(l), true); v != nil {
			return v
		}
	}
	if end := g.safeEnd(l); end > l.releasedEnd {
		l.releasedEnd = end
	}
	return nil
}

// trackPEM follows a private-key block in lane l, searching only text not yet
// searched: it opens on a header, checks the block once from its header when
// the footer arrives, and checks it once as read, as a truncated input, past
// the PEM bound (rel-1-0-10:GAP-0369).
func (g *completionStreamGuard) trackPEM(l *streamGuardLane) *ScanVerdict {
	text := l.text.String()
	from := l.pemScanned
	l.pemScanned = len(text)
	if l.pemStart < 0 {
		// A header may straddle the previous push.
		start := max(0, from-len("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
		at := strings.Index(text[start:], "-----BEGIN ")
		for at >= 0 {
			header := start + at
			if open := secretshape.OpenPrivateKeyPEMStart(text[header:]); open == 0 {
				l.pemStart = header
				return nil
			}
			start = header + 1
			at = strings.Index(text[start:], "-----BEGIN ")
		}
		return nil
	}
	block := text[l.pemStart:]
	if nl := strings.IndexAny(block, "\r\n"); nl < 0 || l.pemStart+nl >= from {
		// The header line was still open at the last push: is it a key?
		if secretshape.OpenPrivateKeyPEMStart(block) != 0 {
			l.pemStart = -1
			return nil
		}
	}
	closed := false
	for !closed {
		if l.pemFooter < 0 {
			search := max(l.pemStart, from-len("-----END "))
			at := strings.Index(text[search:], "-----END ")
			if at < 0 {
				break
			}
			l.pemFooter = search + at
		}
		// The block is closed by its own footer line (secretshape decides),
		// read once the candidate line is there; another END line is skipped.
		if secretshape.OpenPrivateKeyPEMStart(text[l.pemStart:]) != 0 {
			closed = true
			break
		}
		if nl := strings.IndexAny(text[l.pemFooter:], "\r\n"); nl < 0 {
			break // the footer line is still being written
		}
		from = l.pemFooter + 1
		l.pemFooter = -1
	}
	if !closed && len(text)-l.pemStart <= streamGuardPEMBound {
		return nil
	}
	start := l.pemStart
	l.pemStart, l.pemFooter = -1, -1
	if !closed {
		if v := g.Truncate(bounded.Bytes); v != nil {
			return v
		}
	}
	return g.runCheck(l, start, false)
}

// windowStart is where the next local check of lane l starts: all text not
// yet released and streamGuardOverlap bytes before it, but no further back
// than streamGuardOverlap plus streamGuardMaxRun before the unchecked text,
// on a line start when one is near.
func (g *completionStreamGuard) windowStart(l *streamGuardLane) int {
	base := max(l.releasedEnd, l.checkedEnd-streamGuardMaxRun)
	if l.pemStart >= 0 {
		// Behind an open block the release mark stands still; the block is
		// checked from its header when it closes, so the window only needs
		// the new text and its overlap.
		base = l.checkedEnd
	}
	return lineOrRuneStart(l.text.String(), base-streamGuardOverlap)
}

// cloudStart is where the next cloud check of lane l starts.
func (g *completionStreamGuard) cloudStart(l *streamGuardLane) int {
	return lineOrRuneStart(l.text.String(), l.cloudEnd-streamGuardOverlap)
}

func lineOrRuneStart(text string, start int) int {
	if start <= 0 {
		return 0
	}
	if nl := strings.LastIndexByte(text[:start], '\n'); nl >= 0 && start-nl <= streamGuardOverlap {
		// Start on a line so a rule anchored at a line start reads the window
		// as it reads the whole text.
		return nl + 1
	}
	for start < len(text) && !utf8.RuneStart(text[start]) {
		start++
	}
	return start
}

func (g *completionStreamGuard) runCheck(l *streamGuardLane, start int, cloud bool) *ScanVerdict {
	text := l.text.String()
	g.scans++
	check := g.check
	if cloud {
		check = g.cloud
	}
	v := check(text[start:])
	if v != nil && v.Severity != "NONE" && v.Action == guardrailActionBlock {
		g.blocked = v
		g.units = nil
		return v
	}
	if cloud {
		l.cloudEnd = len(text)
	} else {
		l.checkedEnd = len(text)
	}
	return nil
}

// safeEnd is the end of lane l's text a clean check allows to release.
func (g *completionStreamGuard) safeEnd(l *streamGuardLane) int {
	text := l.text.String()
	end := l.checkedEnd - streamGuardHoldback
	if run := trailingRunStart(text[:l.checkedEnd]); run < end {
		end = run
	}
	if l.pemStart >= 0 && l.pemStart < end {
		end = l.pemStart
	}
	if g.cloud != nil && l.cloudEnd < end-streamGuardCloudEvery {
		// The cloud lane may still find something in text it has not read.
		end = l.cloudEnd + streamGuardCloudEvery
	}
	if end < l.releasedEnd {
		end = l.releasedEnd
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

// release returns the units every lane has released the text before, in
// order.
func (g *completionStreamGuard) release() [][]byte {
	n := 0
	for n < len(g.units) && g.unitReleased(g.units[n]) {
		n++
	}
	return g.take(n)
}

func (g *completionStreamGuard) releaseAll() [][]byte { return g.take(len(g.units)) }

func (g *completionStreamGuard) unitReleased(u streamGuardUnit) bool {
	for i, end := range u.ends {
		if g.lanes[i].releasedEnd < end {
			return false
		}
	}
	return true
}

func (g *completionStreamGuard) take(n int) [][]byte {
	if n == 0 {
		return nil
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = g.units[i].data
	}
	g.units = append(g.units[:0], g.units[n:]...)
	return out
}

// streamGuardCheck is the enforced local check a proxy stream runs on each
// guard window: the regex-only mid-stream inspection without the cloud lane,
// with a confirm verdict resolved as for any completion, at most once per
// response (a later window that still holds the finding reuses the answer).
// Nil (release at once) unless mode is action.
func (p *GuardrailProxy) streamGuardCheck(ctx context.Context, r *http.Request, model, mode string) func(string) *ScanVerdict {
	if mode != "action" {
		return nil
	}
	confirm := p.streamConfirmOnce(ctx, r, model, mode)
	return func(window string) *ScanVerdict {
		return confirm(p.inspector.InspectMidStream(ctx, "completion", window, nil, model, mode))
	}
}

// streamGuardCloud is the enforced check with the cloud lane, run every
// streamGuardCloudEvery bytes and at the end of the stream; nil when the
// inspector has no cloud lane or mode is not action.
func (p *GuardrailProxy) streamGuardCloud(ctx context.Context, r *http.Request, model, mode string) func(string) *ScanVerdict {
	if mode != "action" || p.inspector == nil {
		return nil
	}
	if g, ok := p.inspector.(*GuardrailInspector); !ok || !g.hasCloudLane() {
		// A test double or an inspector with no cloud lane: local checks only.
		return nil
	}
	confirm := p.streamConfirmOnce(ctx, r, model, mode)
	return func(window string) *ScanVerdict {
		return confirm(p.inspector.InspectMidStream(ctx, "completion", window,
			[]ChatMessage{{Role: "assistant", Content: window}}, model, mode))
	}
}

// streamConfirmOnce resolves a confirm verdict of one response once: the
// first is asked (resolveConfirm), and every later confirm of the same
// response takes that answer instead of asking again.
func (p *GuardrailProxy) streamConfirmOnce(_ context.Context, r *http.Request, model, mode string) func(*ScanVerdict) *ScanVerdict {
	return confirmOnce(func(verdict *ScanVerdict) {
		p.resolveConfirm(r.Context(), r, verdict, "completion", model, mode)
	})
}

// confirmOnce asks resolve for the first confirm verdict and gives every
// later one the same answer.
func confirmOnce(resolve func(*ScanVerdict)) func(*ScanVerdict) *ScanVerdict {
	asked, answer := false, ""
	return func(verdict *ScanVerdict) *ScanVerdict {
		if verdict == nil || verdict.Action != guardrailActionConfirm {
			return verdict
		}
		if asked {
			verdict.Action = answer
			verdict.Reason = appendVerdictReason(verdict.Reason, "answered earlier in this response")
			return verdict
		}
		resolve(verdict)
		asked, answer = true, verdict.Action
		return verdict
	}
}

// streamGuardLimit is the verdict of a truncated stream in this request's
// pack: a blocking evaluation-limit verdict where the unknown tier blocks
// (strict, rel-1-0-10 one bound rule), nil where it alerts (the final verdict
// carries the truncation then, streamTruncationVerdict).
func (p *GuardrailProxy) streamGuardLimit(ctx context.Context, mode string) func(bounded.CapSet) *ScanVerdict {
	if mode != "action" {
		return nil
	}
	return func(set bounded.CapSet) *ScanVerdict {
		if bounded.Floor(bounded.Allow, set, p.streamTier(ctx)) != bounded.Block {
			return nil
		}
		return streamTruncationVerdict(set, guardrailActionBlock)
	}
}

// streamTier is the pack tier of a proxy request.
func (p *GuardrailProxy) streamTier(ctx context.Context) bounded.Tier {
	cfg := proxyDecisionConfig(ctx)
	if cfg == nil {
		return bounded.TierDefault
	}
	return bounded.TierOf(cfg.HookPolicyTierForConnector(p.proxyRequestConnector(ctx)))
}

// streamTruncationVerdict is the evaluation-limit verdict of a stream read
// up to the caps in set.
func streamTruncationVerdict(set bounded.CapSet, action string) *ScanVerdict {
	severity := "MEDIUM"
	if action == guardrailActionBlock {
		severity = "HIGH"
	}
	reason := set.Reason()
	return &ScanVerdict{
		Action: action, Severity: severity, Scanner: "local-pattern",
		Reason:   "the reply was read up to a bound: " + reason,
		Findings: []string{evaluationLimitRuleID + ":" + boundedTruncatedTitle + " (" + reason + ")"},
	}
}

// withStreamTruncation raises the final verdict of a stream the guard read up
// to a cap to at least the alert of the unknown tier, so a truncation is
// never silent.
func withStreamTruncation(verdict *ScanVerdict, set bounded.CapSet) *ScanVerdict {
	if !set.Any() {
		return verdict
	}
	limit := streamTruncationVerdict(set, guardrailActionAlert)
	if verdict == nil || verdict.Action == "" || verdict.Action == guardrailActionAllow {
		return limit
	}
	merged := *verdict
	merged.Findings = append(append([]string(nil), verdict.Findings...), limit.Findings...)
	merged.Reason = appendVerdictReason(verdict.Reason, limit.Reason)
	return &merged
}

// streamGuardScanEvery is guardrail.stream_buffer_bytes: how much new text a
// stream collects before it is checked and released.
func (p *GuardrailProxy) streamGuardScanEvery() int {
	if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
		return p.cfg.StreamBufferBytes
	}
	return streamGuardScanEvery
}

// newProxyStreamGuard is the guard of one proxy stream: local checks on every
// window, the cloud lane on its cadence, the pack's truncation tier.
func (p *GuardrailProxy) newProxyStreamGuard(ctx context.Context, r *http.Request, model, mode string) *completionStreamGuard {
	return newCompletionStreamGuard(p.streamGuardCheck(ctx, r, model, mode), p.streamGuardScanEvery()).
		withCloud(p.streamGuardCloud(ctx, r, model, mode)).
		withLimit(p.streamGuardLimit(ctx, mode))
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

// hasCloudLane reports an inspector whose checks call Cisco AI Defense
// (scanner mode remote or both, outside managed mode).
func (g *GuardrailInspector) hasCloudLane() bool {
	if g == nil || g.managedMode || (g.scannerMode != "remote" && g.scannerMode != "both") {
		return false
	}
	return g.currentCiscoInspector() != nil
}
