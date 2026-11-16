// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// maximumLifecycleOutput bounds what Setup keeps of a lifecycle child's
// output, the recovery child's included.
const maximumLifecycleOutput = 2 << 20

// enterpriseSetupRecoveryTimeout bounds the one recovery child Setup runs
// after a timed-out lifecycle child; a seam for tests.
var enterpriseSetupRecoveryTimeout = 10 * time.Minute

// enterpriseSetupInitTime is when this process initialized, the start time
// where Windows cannot give the process creation time.
var enterpriseSetupInitTime = time.Now()

// minimumEnterpriseLifecycleStart is the least of TIMEOUTSECONDS a standalone
// mutation or uninstall needs left to start its lifecycle child: the
// shortest TIMEOUTSECONDS, and the shortest --timeout-seconds the ensure
// child accepts.
const minimumEnterpriseLifecycleStart = 60 * time.Second

// enterpriseEnsureChildLimit is the ensure deadline Setup hands its CLI
// child from what is left of TIMEOUTSECONDS: that less a tenth of it (at
// most two minutes), so the child ends with its own lifecycle_timeout and
// service start-mode restore before Setup stops its process tree (GAP-2265:
// the child kept a fixed 12 minutes and an upgrade on a busy host failed
// with most of the 30-minute default left). ok is false when that is under
// the child's 60-second minimum: a child given 60 seconds then would
// outlive Setup's own deadline and be stopped mid-transaction instead.
func enterpriseEnsureChildLimit(remaining time.Duration) (limit time.Duration, ok bool) {
	if remaining <= 0 {
		return 0, false
	}
	margin := remaining / 10
	if margin > 2*time.Minute {
		margin = 2 * time.Minute
	}
	limit = (remaining - margin).Truncate(time.Second)
	return limit, limit >= minimumEnterpriseLifecycleStart
}

// enterpriseEnsureChildTimeoutSeconds is the --timeout-seconds Setup hands
// its ensure child. A run that counts from Setup's start never starts a
// child with too little left (enterpriseLifecycleChildTooLate); without a
// start time the child gets at least its 60-second minimum. Zero (no limit
// known) keeps the child's default.
func enterpriseEnsureChildTimeoutSeconds(remaining time.Duration) int {
	if remaining <= 0 {
		return 0
	}
	limit, ok := enterpriseEnsureChildLimit(remaining)
	if !ok {
		limit = minimumEnterpriseLifecycleStart
	}
	return int(limit / time.Second)
}

// enterpriseLifecycleChildTooLate reports a standalone mutation or
// uninstall whose TIMEOUTSECONDS, counted from Setup's start, has too
// little left to start the lifecycle child: under 60 seconds, or for
// /ensure under what gives the child its own deadline before Setup's
// (GAP-2509 review). Setup's limit would stop such a child, most likely
// mid-transaction, and leave the result to the recovery. Read-only actions
// and runs without a start time are not refused.
func enterpriseLifecycleChildTooLate(opts enterpriseSetupOptions, remaining time.Duration) bool {
	if !opts.Standalone || opts.Started.IsZero() ||
		!enterpriseSetupMutation(opts.Action, true) && opts.Action != "uninstall" {
		return false
	}
	if opts.Action == "ensure" {
		_, ok := enterpriseEnsureChildLimit(remaining)
		return !ok
	}
	return remaining < minimumEnterpriseLifecycleStart
}

// enterpriseSetupStartFromCreation is the process start time on this
// process's monotonic clock: now less the process age, so a wall-clock step
// after the start (a w32time correction at boot, a snapshot restore) does
// not move the TIMEOUTSECONDS deadline. Zero when creation is not usable.
func enterpriseSetupStartFromCreation(now, creation time.Time) time.Time {
	if creation.Year() <= 2000 || creation.After(now) {
		return time.Time{}
	}
	return now.Add(-now.Sub(creation))
}

// enterpriseSetupLifecycleDeadline is when the TIMEOUTSECONDS limit of a run
// ends: opts.Started plus the limit for a standalone Setup, so the payload
// checks and unpacking count (GAP-2509), else now plus the limit.
func enterpriseSetupLifecycleDeadline(opts enterpriseSetupOptions, now time.Time) time.Time {
	if opts.Started.IsZero() || opts.Started.After(now) {
		return now.Add(opts.LifecycleTimeout)
	}
	return opts.Started.Add(opts.LifecycleTimeout)
}

// enterpriseLifecycleChildRun is one lifecycle child Setup ran under
// TIMEOUTSECONDS, and the recovery it ran when that limit stopped the child.
type enterpriseLifecycleChildRun struct {
	output   []byte
	runErr   error
	timedOut bool
	// cause is the timeout context's error when timedOut.
	cause error
	// notStarted is a run whose TIMEOUTSECONDS ended before the lifecycle
	// child started: nothing ran, so nothing is recovered.
	notStarted  bool
	recovery    *enterprisestatus.Result
	recoveryErr error
}

// runEnterpriseLifecycleChild runs the lifecycle child with run under the
// TIMEOUTSECONDS limit, which kills the child's process tree. A standalone
// mutation or uninstall stopped there can leave its transaction pending with
// the services stopped, so Setup then runs recoverChild once, bounded on its
// own, before it returns: the caller removes the staged payload both
// children run from only afterwards (GAP-0501).
func runEnterpriseLifecycleChild(
	parent context.Context,
	opts enterpriseSetupOptions,
	run func(context.Context) ([]byte, error),
	recoverChild func(context.Context) ([]byte, error),
) enterpriseLifecycleChildRun {
	deadline := enterpriseSetupLifecycleDeadline(opts, time.Now())
	ctx, cancel := context.WithDeadline(parent, deadline)
	var result enterpriseLifecycleChildRun
	err := ctx.Err()
	if err == nil && enterpriseLifecycleChildTooLate(opts, time.Until(deadline)) {
		err = context.DeadlineExceeded
	}
	if err != nil {
		// The payload checks and unpacking used up the limit, or left too
		// little to start the lifecycle (it counts from Setup's start,
		// GAP-2509): the child is not started, so the deployment is as it
		// was and needs no recovery.
		cancel()
		result.timedOut, result.notStarted, result.cause = true, true, err
		return result
	}
	result.output, result.runErr = run(ctx)
	result.cause = ctx.Err()
	result.timedOut = result.cause != nil
	cancel()
	recoverable := opts.Standalone && (enterpriseSetupMutation(opts.Action, true) || opts.Action == "uninstall")
	if recoverable && !result.timedOut && enterpriseLifecycleChildEndedAtItsDeadline(result.output, result.runErr) {
		// The standalone ensure child ends itself shortly before
		// TIMEOUTSECONDS (the deadline Setup hands it, GAP-2265). It stopped
		// for the same limit, possibly after its transaction committed and
		// before the scanner runtime step, so it gets the same recovery
		// (GAP-2456: without it verify failed scanner_runtime_unavailable
		// until a manual /repair).
		result.timedOut = true
		result.cause = context.DeadlineExceeded
	}
	if result.timedOut && recoverable {
		result.recovery, result.recoveryErr = recoverTimedOutStandaloneLifecycle(parent, recoverChild)
	}
	return result
}

// enterpriseLifecycleChildEndedAtItsDeadline reports a lifecycle child that
// exited with its own schema-2 lifecycle_timeout result: it ended at the
// deadline Setup handed it, before Setup stopped its process tree.
func enterpriseLifecycleChildEndedAtItsDeadline(output []byte, runErr error) bool {
	if runErr == nil || len(output) > maximumLifecycleOutput {
		return false
	}
	document, _ := splitStandaloneLifecycleJSON(output)
	var report enterprisestatus.Result
	if json.Unmarshal(document, &report) != nil || report.SchemaVersion != 2 || report.Profile != "standalone" {
		return false
	}
	for _, message := range report.Errors {
		if message.Code == "lifecycle_timeout" {
			return true
		}
	}
	return false
}

// standaloneRecoveryOptions are the options of the recovery child: the
// hidden recover action with a JSON result, and none of the request-only
// switches of the run it follows. FORCE, PURGE, NOSTART and the
// attestations belonged to the interrupted request, which is not repeated.
func standaloneRecoveryOptions(opts enterpriseSetupOptions) enterpriseSetupOptions {
	opts.Action = "recover"
	opts.JSON = true
	opts.NoStart = false
	opts.Force = false
	opts.Purge = false
	opts.AttestAgentApplicationControl = false
	opts.AttestClaudeEffectivePolicy = false
	return opts
}

// recoverTimedOutStandaloneLifecycle runs the recovery child under its own
// limit: the parent's timeout already fired, and a cancelled parent must not
// cut the recovery short either. It returns the recovered status only when
// the child proved it: a schema-2 recover result that is ok, exited 0, has
// no error and no pending transaction. Otherwise it returns why not, with
// the first error the recovery reported, so the manual step is not a guess.
func recoverTimedOutStandaloneLifecycle(parent context.Context, recoverChild func(context.Context) ([]byte, error)) (*enterprisestatus.Result, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), enterpriseSetupRecoveryTimeout)
	defer cancel()
	output, runErr := recoverChild(ctx)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("replay pending lifecycle transaction within %s: %w", enterpriseSetupRecoveryTimeout, ctx.Err())
	}
	if len(output) > maximumLifecycleOutput {
		return nil, fmt.Errorf("recovery report exceeded %d bytes", maximumLifecycleOutput)
	}
	document, _ := splitStandaloneLifecycleJSON(output)
	var report enterprisestatus.Result
	decodeErr := json.Unmarshal(document, &report)
	if runErr != nil {
		if decodeErr == nil && len(report.Errors) != 0 {
			return nil, fmt.Errorf("replay pending lifecycle transaction: %w: %s", runErr, boundedRecoveryMessage(report.Errors[0].Message))
		}
		return nil, fmt.Errorf("replay pending lifecycle transaction: %w", runErr)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("decode transaction recovery report: %w", decodeErr)
	}
	if report.SchemaVersion != 2 || report.Action != "recover" ||
		report.Profile != "standalone" || report.Platform != "windows" || !report.OK ||
		report.ExitCode != 0 || len(report.Errors) != 0 || report.TransactionPending {
		return nil, errors.New("transaction recovery did not prove a settled deployment state")
	}
	return &report, nil
}

func boundedRecoveryMessage(message string) string {
	const limit = 512
	if len(message) > limit {
		return message[:limit] + "..."
	}
	return message
}

// timedOutEnterpriseLifecycleError is Setup's error for a child that
// TIMEOUTSECONDS stopped. A standalone run names its recovery: the status
// Setup's recovery proved, or the manual LocalSystem ensure when it proved
// nothing.
func timedOutEnterpriseLifecycleError(opts enterpriseSetupOptions, run enterpriseLifecycleChildRun) error {
	if !opts.Standalone {
		return fmt.Errorf("enterprise %s exceeded the bounded %s timeout: %w", opts.Action, opts.LifecycleTimeout, run.cause)
	}
	if run.notStarted {
		return standaloneEnterpriseSetupTimeoutBeforeLifecycle(opts, run.cause)
	}
	if run.recovery != nil {
		return standaloneEnterpriseSetupTimeoutWithRecovery(opts, run.cause, run.recovery)
	}
	if run.recoveryErr != nil {
		return fmt.Errorf("%w; Setup's bounded transaction recovery failed: %v",
			standaloneEnterpriseSetupTimeout(opts, run.cause), run.recoveryErr)
	}
	return standaloneEnterpriseSetupTimeout(opts, run.cause)
}
