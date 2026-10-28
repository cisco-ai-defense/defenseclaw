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

// enterpriseLifecycleChildRun is one lifecycle child Setup ran under
// TIMEOUTSECONDS, and the recovery it ran when that limit stopped the child.
type enterpriseLifecycleChildRun struct {
	output   []byte
	runErr   error
	timedOut bool
	// cause is the timeout context's error when timedOut.
	cause       error
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
	ctx, cancel := context.WithTimeout(parent, opts.LifecycleTimeout)
	var result enterpriseLifecycleChildRun
	result.output, result.runErr = run(ctx)
	result.cause = ctx.Err()
	result.timedOut = result.cause != nil
	cancel()
	if result.timedOut && opts.Standalone &&
		(enterpriseSetupMutation(opts.Action, true) || opts.Action == "uninstall") {
		result.recovery, result.recoveryErr = recoverTimedOutStandaloneLifecycle(parent, recoverChild)
	}
	return result
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
	if run.recovery != nil {
		return standaloneEnterpriseSetupTimeoutWithRecovery(opts, run.cause, run.recovery)
	}
	if run.recoveryErr != nil {
		return fmt.Errorf("%w; Setup's bounded transaction recovery failed: %v",
			standaloneEnterpriseSetupTimeout(opts, run.cause), run.recoveryErr)
	}
	return standaloneEnterpriseSetupTimeout(opts, run.cause)
}
