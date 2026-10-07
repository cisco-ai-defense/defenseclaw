//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// The helper's half of DefenseClaw's kernel controls on managed Linux. The
// policy work lives in internal/sensor/kernelpolicy; this file reads the
// root-owned inputs (the lifecycle's drop-in, the guardian manifest) and starts
// the reconciler with a Tetragon connection the caller has already
// trust-checked. It takes the connection and the environment as arguments, so
// it has no opinion about how the event stream is wired.

// Exit codes of the cleanup, for the lifecycle and the package scripts.
const (
	cleanupOK          = 0
	cleanupFailed      = 1
	cleanupUnreachable = 3
)

// kernelPolicyIntent reads the drop-in. A malformed value falls back to the
// narrower default and is logged, never fatal: the gateway depends on this
// service and must not lose hooks over a kernel-control setting.
func kernelPolicyIntent(lookup kernelpolicy.Lookup, logger *slog.Logger) kernelpolicy.Intent {
	intent := kernelpolicy.IntentFromLookup(lookup)
	for _, problem := range intent.Problems {
		logger.Warn("tetragon setting ignored; using the safe default", "problem", problem)
	}
	return intent
}

// kernelPolicyStart runs the reconciler until ctx ends and returns it, so the
// event source can feed it hits and loss signals and the broker can publish
// its status. It returns at once; the work is on the controller's goroutine.
//
// In modes off and consume the controller only retires the names an earlier
// run recorded, then stops talking to Tetragon.
func kernelPolicyStart(ctx context.Context, logger *slog.Logger, intent kernelpolicy.Intent, dial kernelpolicy.DialFunc,
	manifestPath string) *kernelpolicy.Controller {
	controller := kernelpolicy.New(kernelpolicy.Config{
		Intent: intent,
		Dirs:   kernelpolicy.DefaultDirs(),
		Logger: logger,
		Dial:   dial,
		Enrollment: func() (kernelpolicy.Enrollment, error) {
			return kernelpolicy.LoadEnrollment(manifestPath, validateManifestTrust, lookupUser)
		},
		ExtraPrefixes: agentPrefixes(os.LookupEnv),
	})
	logger.Info("kernel policy controller starting", "mode", intent.Mode, "kernel_policy", kernelpolicy.Digest(),
		"burn_in", intent.BurnIn.String(), "enforce_ack_set", intent.EnforceAck != "",
		"enforce_connectors", intent.EnforceConnectors)
	go func() {
		if err := controller.Run(ctx); err != nil {
			logger.Error("kernel policy controller stopped", "error", err)
		}
	}()
	return controller
}

// agentPrefixes are the administrator's extra agent install prefixes
// (enrollment.agent_prefixes), which the lifecycle renders into the helper's
// 40-defenseclaw-agent-prefixes.conf drop-in as it does for the enumerator and
// the guardian. They are read straight from the environment, the way
// internal/enterprisehooks reads them: the registry marks the variable
// managed: ignore so a user's environment cannot widen a gateway's trust, but
// this process's environment is the root-owned unit's.
func agentPrefixes(lookup kernelpolicy.Lookup) []string {
	if lookup == nil {
		return nil
	}
	value, _ := lookup(trustedBinPrefixesEnv)
	return filepath.SplitList(value)
}

// trustedBinPrefixesEnv is enterprisehooks.TrustedBinPrefixesEnv.
const trustedBinPrefixesEnv = "DEFENSECLAW_TRUSTED_BIN_PREFIXES"

func lookupUser(name string) (int, string, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, "", err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, "", err
	}
	return uid, account.HomeDir, nil
}

// kernelPolicyCleanup is the body of `--tetragon-cleanup`: the
// one-shot retire of every policy this helper recorded, run with the binary
// that loaded them before binaries or state go away (uninstall, purge,
// rollback, downgrade). It calls ListTracingPolicies and DeleteTracingPolicy
// only, and deletes only names that are both recorded and shaped like the
// ones this helper loads.
//
// It returns an exit code: 0 for done or nothing to do, 3 when Tetragon is
// not reachable while names are still recorded (the lifecycle warns and
// goes on), 1 for an incomplete or refused cleanup. --check is answered by
// runTetragonCleanup before this runs.
func kernelPolicyCleanup(ctx context.Context, logger *slog.Logger, out io.Writer, dirs kernelpolicy.Dirs,
	dial kernelpolicy.DialFunc) int {
	recorded, err := kernelpolicy.Recorded(dirs)
	if err != nil {
		fmt.Fprintf(out, "tetragon-cleanup: cannot read the record of loaded policies: %v\n", err)
		return cleanupFailed
	}
	if len(recorded) == 0 {
		// Nothing was loaded, so there is nothing to reach Tetragon for; an
		// uninstall must not depend on the customer's agent being up.
		fmt.Fprintln(out, "tetragon-cleanup: no recorded policies")
		return cleanupOK
	}
	// A helper in observe or enforce manages these policies: removing them
	// under it would read as an operator's deletion and keep them away until
	// the intent changes. The lifecycle and the package scripts stop it first.
	unlock, err := kernelpolicy.LockForCleanup(dirs)
	switch {
	case errors.Is(err, kernelpolicy.ErrReconcilerRunning):
		fmt.Fprintf(out, "tetragon-cleanup: %v; %d recorded policies left in place: %v\n", err, len(recorded), recorded)
		return cleanupFailed
	case err != nil:
		fmt.Fprintf(out, "tetragon-cleanup: reconciler lock unavailable: %v; %d recorded policies left in place\n", err, len(recorded))
		logger.Warn("tetragon cleanup refused without the reconciler lock", "error", err)
		return cleanupFailed
	default:
		defer unlock()
	}
	client, closeFn, err := dial(ctx)
	if err != nil {
		fmt.Fprintf(out, "tetragon-cleanup: Tetragon is not reachable (%v); %d recorded policies remain: %v\n", err, len(recorded), recorded)
		fmt.Fprintln(out, "tetragon-cleanup: policies added over gRPC do not survive a Tetragon restart: systemctl restart tetragon")
		logger.Warn("tetragon cleanup could not reach Tetragon", "error", err)
		return cleanupUnreachable
	}
	if closeFn != nil {
		defer closeFn()
	}
	result, err := kernelpolicy.Cleanup(ctx, client, dirs)
	for _, name := range result.Removed {
		fmt.Fprintln(out, "removed", name)
	}
	for _, name := range result.Missing {
		fmt.Fprintln(out, "already gone", name)
	}
	for _, name := range result.Kept {
		fmt.Fprintln(out, "kept", name)
	}
	for _, name := range result.Foreign {
		fmt.Fprintln(out, "left alone (not recorded by this helper)", name)
	}
	if err != nil {
		fmt.Fprintf(out, "tetragon-cleanup: %v\n", err)
		logger.Warn("tetragon cleanup incomplete", "error", err)
		return cleanupFailed
	}
	return cleanupOK
}
