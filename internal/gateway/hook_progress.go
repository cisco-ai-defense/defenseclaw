// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A hook of a tool call waits at most hookexec's answer budget (about four
// seconds) for the gateway's decision and then fails closed, so a restart, a
// repair or a busy host never holds the agent's tool call longer than that.
// A decision that waits on a remote scanner (Cisco AI Defense, the LLM
// judge) can take longer for a good reason: the gateway then reports it with
// one informational 102 response, and the hook keeps its whole budget. Only
// requests that carry hookexec.HookProgressHeader get the report; other
// clients never see an informational response.

type hookProgressContextKey struct{}

// hookProgressWriter sends the 102 report at most once, and never after the
// final status or the first body byte, or after the handler returned.
type hookProgressWriter struct {
	http.ResponseWriter
	// start is when the gateway got the call: the hook waits for its
	// answer up to about the hookexec progress ceiling from then.
	start time.Time
	mu    sync.Mutex
	final bool
	sent  bool
}

// withHookProgress returns w and r ready to report progress when r asks for
// it, and the function the handler defers to close the window.
func withHookProgress(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request, func()) {
	start := time.Now()
	r = r.WithContext(context.WithValue(r.Context(), hookRequestStartKey{}, start))
	if r.Header.Get(hookexec.HookProgressHeader) != "1" {
		return w, r, func() {}
	}
	progress := &hookProgressWriter{ResponseWriter: w, start: start}
	ctx := context.WithValue(r.Context(), hookProgressContextKey{}, progress)
	return progress, r.WithContext(ctx), progress.close
}

type hookRequestStartKey struct{}

type shellToolGateKey struct{}

// shellHookBoundsToolGate reports a tool-gate call of a per-user shell hook
// that bounds its wait without asking for progress reports: the Claude Code
// and Codex shell hooks give PreToolUse and PermissionRequest 4 s in all
// (curl --max-time, _hardening.sh defenseclaw_tool_gate_max_time).
func shellHookBoundsToolGate(connector, event string, r *http.Request) bool {
	if r.Header.Get(hookexec.HookProgressHeader) == "1" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode", "codex":
	default:
		return false
	}
	event = strings.TrimSpace(event)
	return event == "PreToolUse" || event == "PermissionRequest"
}

// shellToolGateDefaultWindow is how long such a call's judge may hold the
// answer when the hook did not say how long it waits (the curl transport,
// an older helper): the 4 s of the hook less its own start, the helper's
// 1 s reserve and the answer's way back.
const shellToolGateDefaultWindow = 2 * time.Second

// shellToolGateAnswerMargin is kept from the wait the hook names for the
// rest of the decision and the answer's way back.
const shellToolGateAnswerMargin = 300 * time.Millisecond

// withShellToolGateBound marks ctx as such a call. Its hook-lane judge then
// answers inside the hook's wait (HookAnswerWithinHeader less a margin,
// shellToolGateDefaultWindow without it, never over hookJudgeAnswerWindow),
// as for a bounded native hook. It used to hold the answer for the judge's
// whole hook_timeout (8 s), past the hook's own 4 s, and the hook then failed
// the benign call closed whenever a slow or queued judge took longer than
// the hook waited (#1395).
func withShellToolGateBound(ctx context.Context, r *http.Request) context.Context {
	start, ok := ctx.Value(hookRequestStartKey{}).(time.Time)
	if !ok || start.IsZero() {
		start = time.Now()
	}
	window := shellToolGateDefaultWindow
	if ms, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(hookexec.HookAnswerWithinHeader))); err == nil && ms > 0 {
		window = time.Duration(ms)*time.Millisecond - shellToolGateAnswerMargin
	}
	window = min(max(window, 0), hookJudgeAnswerWindow)
	return context.WithValue(ctx, shellToolGateKey{}, start.Add(window))
}

// reportHookProgress sends the request's 102 report, if it asked for one.
// The decision path calls it on the request's goroutine before it waits on a
// remote scanner.
func reportHookProgress(ctx context.Context) {
	if ctx == nil {
		return
	}
	if progress, ok := ctx.Value(hookProgressContextKey{}).(*hookProgressWriter); ok {
		progress.report()
	}
}

// hookJudgeAnswerWindow is how long after the gateway got a bounded hook
// call a hook-lane judge may hold its answer. The hook waits about 4 s from
// its own start once the gateway reported progress (hookexec
// hookProgressCeiling) and then fails closed, so a judge that took longer
// turned a benign prompt into enterprise_managed_gateway_no_answer, even in
// observe mode (GAP-2625). The window leaves the hook start, the rest of the
// decision and the answer about 600 ms of that ceiling.
const hookJudgeAnswerWindow = 3400 * time.Millisecond

// hookJudgeAnswerEnd is the latest time a hook-lane judge may hold the
// answer of the call on ctx, and false when the call has no bounded answer
// (its hook did not ask for progress reports: Secure Client, session events,
// in-process callers).
func hookJudgeAnswerEnd(ctx context.Context) (time.Time, bool) {
	if ctx == nil {
		return time.Time{}, false
	}
	progress, ok := ctx.Value(hookProgressContextKey{}).(*hookProgressWriter)
	if ok && progress != nil && !progress.start.IsZero() {
		return progress.start.Add(hookJudgeAnswerWindow), true
	}
	if end, ok := ctx.Value(shellToolGateKey{}).(time.Time); ok && !end.IsZero() {
		return end, true
	}
	return time.Time{}, false
}

func (w *hookProgressWriter) report() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.final || w.sent {
		return
	}
	w.sent = true
	w.ResponseWriter.WriteHeader(hookexec.HookProgressStatus)
}

func (w *hookProgressWriter) close() {
	w.mu.Lock()
	w.final = true
	w.mu.Unlock()
}

// begin marks the final answer and reports whether this call is the first.
func (w *hookProgressWriter) begin() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	first := !w.final
	w.final = true
	return first
}

func (w *hookProgressWriter) WriteHeader(code int) {
	if code >= 200 {
		w.begin()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hookProgressWriter) Write(p []byte) (int, error) {
	if w.begin() {
		// A body without a status is a 200. Say so, so a wrapper that
		// recorded the 102 records the final status too.
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *hookProgressWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *hookProgressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
