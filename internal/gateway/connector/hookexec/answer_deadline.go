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

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hookAnswerBudget is how long a bounded hook waits for its gateway's
// decision. Per-user hooks count it from process start; managed native hooks
// count it from gateway contact, within managedAnswerDeadlineCap. A restart
// (gatewayRestartBudget), dial, accepted call without an answer, and resends
// after a 429 or 401 all share the call's deadline. Managed and strict hooks
// close at the deadline; a per-user hook follows its configured outage mode
// only for a proven gateway outage. A request with no decision stays closed.
//
// The agent may wait at most 5 s for DefenseClaw, and the deadline itself
// runs late on a loaded host: the answer is written by a process that the
// system schedules, after the deadline, beside the work that holds the CPU.
// With a 4 s budget, managed Windows calls during Setup ensures, a repair
// and a gateway service start gave their block 1.1 to 1.75 s after it
// (5.1-5.75 s; GAP-0155, GAP-0167, GAP-0171). The 3.5 s contact budget
// keeps 1.5 s when it starts promptly; the managed process cap below keeps
// 1 s. The hook also runs above normal priority on Windows
// (cmd/internal/hookpriority).
//
// A gateway that waits on a remote scanner for the call (Cisco AI Defense,
// the LLM judge) says so with an informational 102 response
// (HookProgressHeader); the call then waits up to hookProgressCeiling.
var hookAnswerBudget = 3500 * time.Millisecond

// Codex registers per-user PreToolUse command hooks with a 30-second host
// timeout. Give an otherwise healthy local gateway another half-second under
// host load; the managed hook and the other connectors keep the
// shorter answer budget. This meets the four-second progress ceiling.
var perUserCodexAnswerBudget = 4 * time.Second

// A managed native hook may resolve its protected runtime, scan foreign
// hooks, and exchange their session record before its policy POST. The
// gateway still gets hookAnswerBudget from that contact when it fits; the
// process deadline below limits the whole call to four seconds from launch,
// leaving one second inside the agent's five-second hook cap for a late wake.
// The early watchdog uses this deadline so local work cannot extend the
// process indefinitely. Secure Client keeps its existing deadlines.
var managedAnswerDeadlineCap = 4 * time.Second

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
// through. The process cap still counts from invocation, so a slow local
// step before contact can leave a healthy gateway a few milliseconds and
// turn the expired budget into an allowance (final review, P2). Less than
// this left fails closed (errAnswerBudgetSpentLocally).
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

// HookAnswerWithinHeader carries, in milliseconds, how long a per-user shell
// hook's request waits for the gateway's answer (defenseclaw-hook-post, from
// the shell's _DC_HOOK_POST_DEADLINE_MS). The gateway keeps a tool-call
// judge's wait inside it, since these hooks do not ask for progress reports
// (#1395).
const HookAnswerWithinHeader = "X-DefenseClaw-Hook-Answer-Within-Ms"

// HookDeliveryReceiptHeader selects the full-duplex managed hook protocol.
// The hook sends the receipt only after committing the answer to the agent.
const HookDeliveryReceiptHeader = "X-DefenseClaw-Hook-Delivery-Receipt"

const HookDeliveryPayloadBytesHeader = "X-DefenseClaw-Hook-Payload-Bytes"

const HookDeliveryRequiredHeader = "X-DefenseClaw-Hook-Delivery-Required"

const HookDeliveryReceiptAck = "ack\n"

const HookDeliveryReceiptBlock = "block\n"

// HookDeliveryReceiptLate and HookDeliveryReceiptOpen report the answer the
// watchdog delivered when the gateway had not supplied a usable answer.
const HookDeliveryReceiptLate = "late\n"
const HookDeliveryReceiptOpen = "open\n"

// HookDeliveryReleased ends the request body of a hook whose capability wait
// passed without a 103: the hook takes the ordinary answer and sends no
// receipt. It is JSON whitespace, so an older gateway's decoder ignores it.
const HookDeliveryReleased = "\n"

const HookDeliveryConfirmed = "received\n"

// HookShellBridgeHeader marks the gateway post of a managed standalone shell
// hook (curl over the hook socket, value "shell"). The shell bridge has no
// answer watchdog and asks for no delivery receipt: the agent gets the answer
// the gateway sent, or the closed fallback of the bridge when the request
// fails, so a missing receipt does not make its verdict unconfirmed
// (GAP-2614). The native hook never sends it.
const HookShellBridgeHeader = "X-DefenseClaw-Hook-Bridge"

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
	if opts.ManagedEnterprise {
		return startedAt.Add(managedAnswerDeadlineCap)
	}
	budget := hookAnswerBudget
	if !opts.ManagedEnterprise && strings.EqualFold(strings.TrimSpace(opts.Connector), "codex") &&
		perUserCodexAnswerBudget > budget {
		budget = perUserCodexAnswerBudget
	}
	return startedAt.Add(budget)
}

// gatewayAnswerDeadline is the managed gateway contact's answer window,
// bounded by the process deadline armed before runtime and foreign-hook work.
// A per-user call keeps its invocation-based deadline.
func gatewayAnswerDeadline(opts Options, startedAt, contactAt time.Time) time.Time {
	cap := answerDeadline(opts, startedAt)
	if cap.IsZero() || !opts.ManagedEnterprise {
		return cap
	}
	contactDeadline := contactAt.Add(hookAnswerBudget)
	if contactDeadline.Before(cap) {
		return contactDeadline
	}
	return cap
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

// ToolGateEvent reports a hook event that runs before a tool call (or asks
// for its permission) and blocks it until the hook answers: a block of it is
// the call's verdict. The gateway's hook-failure report uses it to tell the
// hook's own block of a call from a block of a later event of a call that
// already ran (GAP-0271 review).
func ToolGateEvent(connector, event string) bool {
	return toolGateEvent(connector, event)
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
// errGatewayNoAnswer at deadline unless the gateway answered (stopResponse)
// by then.
// A report that the gateway waits on a remote scanner (a 102 response) moves
// the deadline to ceiling, never further (GAP-0255). Call stop after an
// ordinary answer is read. For an answer that needs a receipt, call
// stopResponse after reading it and stop after writing it to the agent; the
// watchdog stays armed until then. Release when the request is done. This
// lets the hook send its receipt after the answer deadline without the
// deadline canceling the HTTP request. watch, when set, takes the ceiling
// at the 102. A zero deadline returns ctx unchanged.
func awaitAnswerBy(ctx context.Context, deadline, ceiling time.Time, watch *answerWatchdog) (watched context.Context, stop, stopResponse, release func()) {
	if deadline.IsZero() {
		noop := func() {}
		return ctx, noop, noop, noop
	}
	if ceiling.Before(deadline) {
		ceiling = deadline
	}
	answered := make(chan struct{})
	progressed := make(chan struct{})
	var answerOnce, progressOnce sync.Once
	stopResponse = func() {
		answerOnce.Do(func() {
			close(answered)
		})
	}
	stop = func() {
		stopResponse()
		watch.answered()
	}
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		if code == HookProgressStatus {
			progressOnce.Do(func() {
				watch.progressed()
				close(progressed)
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
	return watched, stop, stopResponse, func() { stop(); cancel(nil) }
}

// gatewayNoAnswer reports a request ctx that awaitAnswerBy ended.
func gatewayNoAnswer(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errGatewayNoAnswer)
}

// noAnswerFailMode keeps a call with no gateway decision closed. A proven
// outage has its own answer path; socket contact alone does not prove one.
// Secure Client retains its established fail-mode behavior unless the local
// answer budget was spent or the gateway already returned an error status.
func noAnswerFailMode(opts Options, failMode string) string {
	if opts.answerSpentLocally || opts.answeredErrorStatus != 0 || opts.ManagedEnterprise {
		return "closed"
	}
	if opts.SecureClient {
		return failMode
	}
	return "closed"
}

// lateOrdinaryCheck is the scan of a per-user tool call that the verified
// gateway takes and does not answer by the deadline: it reports a call that
// plainly names nothing a protected file could be reached through
// (hookpaths.LateOrdinaryCall). Such a call follows the account's outage mode
// instead of the closed no-answer answer, since a gateway that is up but slow
// under a burst is not a reason to deny ordinary work. nil for managed,
// socket and Secure Client calls and for events that are not a tool gate.
func lateOrdinaryCheck(opts Options, payload []byte) func() bool {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" || opts.SecureClient ||
		!toolGateEvent(opts.Connector, opts.Event) {
		return nil
	}
	connector := opts.Connector
	return func() bool { return hookpaths.LateOrdinaryCall(connector, payload) }
}

func failNoAnswer(opts Options, sp spec, failMode string) int {
	if managedNativeDecision(opts) && opts.answeredErrorStatus != 0 {
		return failAfterErrorStatus(opts, sp, "closed", opts.answeredErrorStatus)
	}
	failMode = noAnswerFailMode(opts, failMode)
	if opts.ManagedEnterprise {
		return failUnreachable(opts, sp, failMode, managedNoAnswerReason(opts))
	}
	if !opts.SecureClient && opts.ManagedUnixSocket == "" {
		opts = withPerUserOutage(opts)
		// Use the mode read for this call in the answer and its failure row.
		opts.OutageFailModeNow = func() string { return failMode }
	}
	return failUnreachable(opts, sp, failMode, noAnswerReason(opts))
}

// managedGatewayServiceStopped reports whether the managed gateway service
// is proven stopped now; tests replace it.
var managedGatewayServiceStopped = platformManagedGatewayServiceStopped

// managedNoAnswerReason is the reason of a managed call the gateway gave no
// decision in time. On a stopped Windows gateway service a stall on the host
// can end the answer budget before the transport reads the service state;
// the call then says the service is not running, as every other call of
// the outage does, not that the gateway did not answer (rel-1-0-3 GAP-0319).
// The fail mode stays the no-answer one. Secure Client keeps its reason.
func managedNoAnswerReason(opts Options) string {
	if opts.managedNoAnswerCode != "" {
		return opts.managedNoAnswerCode
	}
	name := strings.TrimSpace(opts.ManagedGatewayServiceName)
	if !opts.SecureClient && name != "" && managedGatewayServiceStopped(name) {
		return managedGatewayNotRunningReason
	}
	return managedGatewayNoAnswerReason
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
