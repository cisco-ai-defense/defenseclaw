// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// hookAnswerBudget is how long, from the start of the hook process, a tool
// call's hook waits for its gateway's decision. Every wait of the call
// counts against it: a restart (gatewayRestartBudget), a dial, a gateway that
// accepted the call but does not answer (it is stopping, it is starting, or
// it is so busy that the call waits for its turn), and the resends after a
// 429 or a 401. When the budget ends the call fails: closed for a managed
// hook whatever its fail mode, the account's fail mode for a per-user hook
// (closed unless the account chose open). It is never allowed because the
// gateway was slow (GAP-0155, GAP-0167, GAP-0139, GAP-0160).
//
// The agent may wait at most 5 s for DefenseClaw, and the deadline itself
// runs late on a loaded host: the answer is written by a process that the
// system schedules, after the deadline, beside the work that holds the CPU.
// With a 4 s budget, managed Windows calls during Setup ensures, a repair
// and a gateway service start gave their block 1.1 to 1.75 s after it
// (5.1-5.75 s; GAP-0155, GAP-0167, GAP-0171). The budget keeps 1.5 s of the
// 5 s for that slip; the hook also runs above normal priority there
// (cmd/defenseclaw-hook/internal/hookpriority).
//
// A gateway that waits on a remote scanner for the call (Cisco AI Defense,
// the LLM judge) says so with an informational 102 response
// (HookProgressHeader); the call then waits up to hookProgressCeiling.
var hookAnswerBudget = 3500 * time.Millisecond

// hookProgressCeiling is how long, from the start of the hook process, a
// tool call whose gateway reported (102) that it waits on a remote scanner
// may wait for the decision. The 102 only moves the answer deadline to it:
// a scanner that answers later is not waited for, the call fails (closed for
// a managed hook) and the agent's tool call still waits at most about five
// seconds for DefenseClaw. The scanner's late verdict is discarded, like any
// late answer. Before it the 102 lifted the deadline altogether, so a judge
// that took longer held the call to the agent's own hook timeout (GAP-0255).
// It keeps 1 s of the 5 s for the slip of a late deadline.
var hookProgressCeiling = 4 * time.Second

// hookGatewayAnswerFloor is the least time a standalone managed hook's
// gateway contact (the foreign-hook session exchange, or the hook request)
// must have before the call's answer deadline for a missing answer to count
// as the gateway's: an outage that the administrator's open fail mode lets
// through. The deadline counts from the invocation, so a slow local step
// before the contact (a foreign-hook scan that runs close to its own budget)
// could otherwise leave a healthy gateway a few milliseconds and turn the
// expired budget into an allowance (final review, P2). Less than this left
// fails closed (errAnswerBudgetSpentLocally).
var hookGatewayAnswerFloor = time.Second

// errAnswerBudgetSpentLocally marks a missing answer of a gateway contact
// that started with less than hookGatewayAnswerFloor of the answer budget
// left: the hook's own work spent the budget, the gateway did not fail to
// answer. It wraps with errGatewayNoAnswer, keeps its reason code, and is
// closed in every fail mode.
var errAnswerBudgetSpentLocally = errors.New("the hook's own work used the answer budget before the gateway was asked")

// gatewayAnswerWindowShort reports a standalone managed hook whose answer
// deadline leaves its gateway less than hookGatewayAnswerFloor from now.
func gatewayAnswerWindowShort(opts Options, deadline time.Time) bool {
	return managedNativeDecision(opts) && !deadline.IsZero() && time.Until(deadline) < hookGatewayAnswerFloor
}

// HookProgressHeader asks the gateway to answer 102 Processing as soon as a
// tool call it evaluates waits on a remote scanner. Only hooks that bound
// their wait by hookAnswerBudget send it, so other clients never see an
// informational response.
const HookProgressHeader = "X-DefenseClaw-Hook-Progress"

// HookDeliveryReceiptHeader selects the full-duplex managed hook protocol.
// The hook sends the receipt only after committing the answer to the agent.
const HookDeliveryReceiptHeader = "X-DefenseClaw-Hook-Delivery-Receipt"

const HookDeliveryPayloadBytesHeader = "X-DefenseClaw-Hook-Payload-Bytes"

const HookDeliveryRequiredHeader = "X-DefenseClaw-Hook-Delivery-Required"

const HookDeliveryReceiptAck = "ack\n"

const HookDeliveryReceiptBlock = "block\n"

// HookDeliveryReleased ends the request body of a hook whose capability wait
// passed without a 103: the hook takes the ordinary answer and sends no
// receipt. It is JSON whitespace, so an older gateway's decoder ignores it.
const HookDeliveryReleased = "\n"

const HookDeliveryConfirmed = "received\n"

// HookProgressStatus is the informational status of that report.
const HookProgressStatus = http.StatusProcessing

// errGatewayNoAnswer ends a tool call's hook request whose gateway gave no
// decision, and no progress report, within hookAnswerBudget.
var errGatewayNoAnswer = errors.New("the gateway did not answer within the hook's answer budget")

// managedGatewayNoAnswerReason is the hook-failure reason of a managed hook
// whose gateway gave no decision within hookAnswerBudget.
const managedGatewayNoAnswerReason = "enterprise_managed_gateway_no_answer"

// ManagedGatewayNoAnswerReason is managedGatewayNoAnswerReason for callers
// that render the reason themselves.
const ManagedGatewayNoAnswerReason = managedGatewayNoAnswerReason

// ErrManagedGatewayNoAnswer is wrapped by a managed hook transport error
// (ExchangeForeignHookSession) that the answer budget ended.
var ErrManagedGatewayNoAnswer = errGatewayNoAnswer

// ManagedGatewayNoAnswer reports an error from a managed hook transport that
// the answer budget of a tool call ended.
func ManagedGatewayNoAnswer(err error) bool {
	return errors.Is(err, errGatewayNoAnswer)
}

// perUserGatewayNoAnswerReason is the hook-failure reason of a per-user hook
// whose gateway gave no decision within hookAnswerBudget.
const perUserGatewayNoAnswerReason = "gateway did not answer in time"

// answerDeadline bounds hooks that hold an agent call waiting for a verdict.
// Managed Codex also gates prompt submission and delivery of tool results;
// both need the same bounded answer and canonical no-answer reason as a
// pre-tool hook. Secure Client, per-user non-tool events, session and stop
// events keep their whole budget (including longer local component scans).
func answerDeadline(opts Options, startedAt time.Time) time.Time {
	bounded := toolGateEvent(opts.Connector, opts.Event)
	if managedNativeDecision(opts) && strings.EqualFold(strings.TrimSpace(opts.Connector), "codex") {
		event := strings.TrimSpace(opts.Event)
		bounded = bounded || event == "UserPromptSubmit" || event == "PostToolUse"
	}
	if opts.SecureClient || startedAt.IsZero() || !bounded {
		return time.Time{}
	}
	return startedAt.Add(hookAnswerBudget)
}

// progressCeiling is the latest answer deadline of a tool call that started
// at startedAt, after its gateway reported that it waits on a remote
// scanner; zero when the call has no answer deadline.
func progressCeiling(opts Options, startedAt time.Time) time.Time {
	if answerDeadline(opts, startedAt).IsZero() {
		return time.Time{}
	}
	return startedAt.Add(max(hookProgressCeiling, hookAnswerBudget))
}

// toolGateEvent reports a hook event that runs before a tool call (or asks
// for its permission) and blocks it until the hook answers.
func toolGateEvent(connector, event string) bool {
	event = strings.TrimSpace(event)
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode", "codex", "devin", "kiro", "antigravity":
		return event == "PreToolUse" || event == "PermissionRequest"
	case "copilot":
		return event == "preToolUse" || event == "permissionRequest"
	case "cursor":
		switch strings.ToLower(event) {
		case "pretooluse", "beforeshellexecution", "beforemcpexecution", "beforereadfile", "beforetabfileread":
			return true
		}
	case "hermes":
		return event == "pre_tool_call"
	case "opencode":
		return event == "tool.execute.before"
	case "amp":
		return event == "tool.call"
	}
	return false
}

// awaitAnswerBy returns ctx for the hook request of a tool call, ended with
// errGatewayNoAnswer at deadline unless the gateway answered (stop) by then.
// A report that the gateway waits on a remote scanner (a 102 response) moves
// the deadline to ceiling, never further (GAP-0255). Call stop once the final
// response headers are in, before reading the body, and release when the
// request is done. watch, when set, follows both: it stands down at the
// first stop and takes the ceiling at the 102. A zero deadline returns ctx
// unchanged.
func awaitAnswerBy(ctx context.Context, deadline, ceiling time.Time, watch *answerWatchdog) (watched context.Context, stop, release func()) {
	if deadline.IsZero() {
		return ctx, func() {}, func() {}
	}
	if ceiling.Before(deadline) {
		ceiling = deadline
	}
	answered := make(chan struct{})
	progressed := make(chan struct{})
	var answerOnce, progressOnce sync.Once
	stop = func() {
		answerOnce.Do(func() {
			close(answered)
			watch.answered()
		})
	}
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		if code == HookProgressStatus {
			progressOnce.Do(func() {
				close(progressed)
				watch.progressed()
			})
		}
		return nil
	}}
	watched, cancel := context.WithCancelCause(httptrace.WithClientTrace(ctx, trace))
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		progress := progressed
		for {
			select {
			case <-answered:
				return
			case <-watched.Done():
				return
			case <-progress:
				// The scanner may answer up to the ceiling, not longer.
				progress = nil
				timer.Reset(time.Until(ceiling))
			case <-timer.C:
				select {
				case <-answered:
				default:
					cancel(errGatewayNoAnswer)
				}
				return
			}
		}
	}()
	return watched, stop, func() { stop(); cancel(nil) }
}

// gatewayNoAnswer reports a request ctx that awaitAnswerBy ended.
func gatewayNoAnswer(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errGatewayNoAnswer)
}

// noAnswerFailMode keeps managed non-tool events, locally spent budgets and a
// call the gateway answered 429 first (Options.gatewayBusy,
// ManagedOutageFailsOpen) closed. No answer proves no gateway decision, so
// every managed hook closes; per-user hooks keep their installed fail mode.
// failNoAnswer and renderNoAnswer both use it, so the decision and failure
// row agree.
func noAnswerFailMode(opts Options, failMode string) string {
	if opts.answerSpentLocally || opts.gatewayBusy || opts.ManagedEnterprise {
		return "closed"
	}
	return failMode
}

func failNoAnswer(opts Options, sp spec, failMode string) int {
	failMode = noAnswerFailMode(opts, failMode)
	if opts.ManagedEnterprise {
		return failUnreachable(opts, sp, failMode, managedGatewayNoAnswerReason)
	}
	return failUnreachable(opts, sp, failMode, noAnswerReason(opts))
}

// noAnswerReason is the hook-failure reason of a call whose gateway gave no
// decision in time.
func noAnswerReason(opts Options) string {
	if opts.ManagedEnterprise {
		return managedGatewayNoAnswerReason
	}
	return perUserGatewayNoAnswerReason
}

// errGatewayTookCallNoAnswer wraps the error of a hook request whose
// connection to the gateway was made and whose own timeout then ran out
// while it waited for the answer: the gateway was reached and stalled, it
// was not unreachable. A stop or session event has no answer budget, so
// this is how its stall ends (GAP-0527).
var errGatewayTookCallNoAnswer = errors.New("the gateway took the call and did not answer before the request timed out")

// markConnectedTimeout wraps err with errGatewayTookCallNoAnswer when the
// request had its connection and then timed out.
func markConnectedTimeout(err error, connected bool) error {
	var netErr net.Error
	if err == nil || !connected || !errors.As(err, &netErr) || !netErr.Timeout() {
		return err
	}
	return fmt.Errorf("%w: %w", errGatewayTookCallNoAnswer, err)
}

// retryFitsAnswer reports whether a resend that starts after delay still
// starts before the answer deadline (always, without one).
func retryFitsAnswer(deadline time.Time, delay time.Duration) bool {
	return deadline.IsZero() || time.Now().Add(delay).Before(deadline)
}
