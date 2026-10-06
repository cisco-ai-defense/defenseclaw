// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// newUnixLifecycleEnv is a seam for CLI tests.
var newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
	return enterpriseunix.NewEnv(goos, appVersion)
}

func platformGOOS(platform string) string {
	if platform == "macos" {
		return "darwin"
	}
	return platform
}

// checkLockWait refuses a --lock-wait outside 0..MaxLockWait the way a
// malformed value is refused: the cap as --help and lifecycle_busy print it
// ("15m", not "15m0s"), the usage line and the --help pointer, exit 2
// (GAP-2028).
func checkLockWait(cmd *cobra.Command, wait time.Duration) error {
	if wait >= 0 && wait <= enterpriseunix.MaxLockWait {
		return nil
	}
	limit := enterpriseunix.FormatLockWait(enterpriseunix.MaxLockWait)
	// Name the value as typed ("not 1h", not "not 60m"; GAP-2329).
	typed := typedLockWait(cmd, wait)
	if typed == "" {
		typed = enterpriseunix.FormatLockWait(wait)
	}
	msg := fmt.Sprintf("--lock-wait takes at most %s, not %s", limit, typed)
	if wait < 0 {
		msg = fmt.Sprintf("--lock-wait takes a duration from 0 to %s, not %s", limit, typed)
	}
	return lifecycleFlagError(cmd, errors.New(msg))
}

func runUnixLifecycle(cmd *cobra.Command, platform, action string, opts *unixLifecycleOptions) error {
	goos := platformGOOS(platform)
	if enterpriseunix.CurrentGOOS() != goos {
		return withExitCode(fmt.Errorf("`enterprise %s` manages %s hosts; this host is %s", platform, goos, enterpriseunix.CurrentGOOS()), enterprisestatus.UnixExitInvalidArgs)
	}
	if err := checkLockWait(cmd, opts.lockWait); err != nil {
		return err
	}
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	ctx := cmd.Context()
	if action == enterpriseunix.ActionRotateCredentials {
		var stop func()
		ctx, stop = settleInterruptedRotation(ctx, cmd.ErrOrStderr(), platform)
		defer stop()
	}
	result := enterpriseunix.Run(ctx, env, enterpriseunix.Options{
		Action:             action,
		PayloadDir:         opts.payload,
		FromPackage:        opts.fromPackage,
		ConfigFile:         opts.config,
		NoStart:            opts.noStart,
		AdoptExisting:      opts.adoptExisting,
		AllowDowngrade:     opts.allowDowngrade,
		Purge:              opts.purge,
		KeepState:          opts.keepState,
		KeepServiceAccount: opts.keepServiceAccount,
		ProductVersion:     opts.productVersion,
		Reason:             opts.reason,
	})
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	return lifecycleFailure(result, opts.json, env.LifecycleCommand(enterpriseunix.ActionRepair))
}

// settleInterruptedRotation makes an interrupt (Ctrl+C, SIGTERM) end
// rotate-credentials with one accepted key: the first one cancels the
// returned context, and the rotation rolls itself back (or, past its commit,
// finishes) before the command exits. A second interrupt exits at once and
// says how to settle what is left.
func settleInterruptedRotation(parent context.Context, w io.Writer, platform string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			fmt.Fprintln(w, "\nrotate-credentials was interrupted; settling the rotation so the gateway accepts one key again. This can take a few minutes; interrupt again to stop at once.")
			cancel()
		case <-done:
			return
		}
		select {
		case sig := <-signals:
			fmt.Fprintf(w, "\nrotate-credentials stopped before the rotation was settled. The gateway may accept the old and the new key for up to %d minutes; run `enterprise %s reconcile` as root now to complete the rotation or roll it back.\n",
				int(connector.RotationKeyMaxAge/time.Minute), platform)
			code := 130
			if sig == syscall.SIGTERM {
				code = 143
			}
			os.Exit(code)
		case <-done:
		}
	}()
	return ctx, func() {
		signal.Stop(signals)
		close(done)
		cancel()
	}
}

// lifecycleFailure is the command error of a failed result. The human
// output has already listed every problem, so the error line only says
// where to look and, for a failed status or verify of an installed
// deployment, names repairCommand as the next step; with --json the
// document is on stdout and the error line on stderr carries the problems.
func lifecycleFailure(result *enterprisestatus.Result, asJSON bool, repairCommand string) error {
	if result.OK {
		return nil
	}
	if asJSON || len(result.Errors) == 0 {
		return withExitCode(errors.New(lifecycleErrorSummary(result)), result.ExitCode)
	}
	message := fmt.Sprintf("%s failed; see the %s listed above", result.Action, countNoun(len(result.Errors), "problem"))
	// A status that found another run in progress checked nothing, so
	// repair is not the next step (GAP-2246).
	if repairCommand != "" && result.Installed && !lifecycleResultHasError(result, "lifecycle_busy") &&
		(result.Action == enterpriseunix.ActionVerify || result.Action == enterpriseunix.ActionStatus) {
		target := "them"
		if len(result.Errors) == 1 {
			target = "it"
		}
		message += ". Run `" + repairCommand + "` as root to fix " + target
	}
	return withExitCode(errors.New(message), result.ExitCode)
}

func printLifecycleResult(w io.Writer, result *enterprisestatus.Result, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	// verify turns target and machine-policy warnings into verify_failed
	// errors; each problem is printed once, as an error with the specific
	// code of the warning it came from.
	warningCode := map[string]string{}
	for _, warning := range result.Warnings {
		if _, seen := warningCode[warning.Message]; !seen {
			warningCode[warning.Message] = warning.Code
		}
	}
	errorMessages := map[string]bool{}
	var errs, warns []string
	for _, e := range result.Errors {
		code := e.Code
		if specific, ok := warningCode[e.Message]; ok && code == "verify_failed" {
			code = specific
		}
		errorMessages[e.Message] = true
		errs = append(errs, code+": "+e.Message)
	}
	for _, warning := range result.Warnings {
		if errorMessages[warning.Message] {
			continue
		}
		warns = append(warns, warning.Code+": "+warning.Message)
	}
	writeLifecycleSummary(w, result.Action, result.OK, result.Noop, result.NoopReason, errs, warns)
	// repair (and an ensure that re-applied) says what it changed.
	for _, change := range result.Changes {
		fmt.Fprintf(w, "  - %s\n", change)
	}
	if result.Action == enterpriseunix.ActionRepair && result.OK {
		if len(result.Changes) == 0 {
			fmt.Fprintln(w, "  nothing to repair")
		}
		// repair re-applies the deployment, so it stops and starts every
		// service even when nothing needed repair; say so (GAP-2030).
		if !lifecycleResultHasWarning(result, "not_started") {
			fmt.Fprintln(w, "  restarted the DefenseClaw services to re-apply the deployment; `ensure` leaves a healthy deployment running")
		}
	}
	// A verify that found the lifecycle lock held checked nothing either:
	// its all-false readiness line read as "not installed" (GAP-1542).
	if (result.Action == enterpriseunix.ActionStatus || result.Action == enterpriseunix.ActionVerify) &&
		!lifecycleResultHasError(result, "not_root") && !lifecycleResultHasError(result, "lifecycle_busy") {
		fmt.Fprintf(w, "  installed=%v version=%s gateway_ready=%v guardian_ready=%v enumerator_ready=%v sensor_helper_ready=%v\n",
			result.Installed, result.InstalledVersion, result.Readiness.Gateway, result.Readiness.Guardian,
			result.Readiness.Enumerator, result.Readiness.SensorHelper)
		if result.Inspection.Local != "" || result.Inspection.AIDefense != "" {
			fmt.Fprintf(w, "  inspection: local=%s ai_defense=%s\n", result.Inspection.Local, result.Inspection.AIDefense)
		}
		for _, service := range result.Services {
			fmt.Fprintf(w, "  %-46s %s\n", service.Name, service.State)
		}
	}
	// A busy status checked nothing else, but still reports the recorded
	// deployment's version, as the docs say (GAP-2409).
	if result.Action == enterpriseunix.ActionStatus && result.Installed && lifecycleResultHasError(result, "lifecycle_busy") {
		fmt.Fprintf(w, "  installed=true version=%s\n", result.InstalledVersion)
	}
	return nil
}

// lifecycleResultHasWarning reports whether result carries a warning with code.
func lifecycleResultHasWarning(result *enterprisestatus.Result, code string) bool {
	for _, warning := range result.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}

// lifecycleResultHasError reports whether result carries an error with code.
// A not_root status and a lifecycle_busy verify know nothing about the
// deployment, so their readiness line (installed=false ...) is left out.
func lifecycleResultHasError(result *enterprisestatus.Result, code string) bool {
	for _, e := range result.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

func lifecycleErrorSummary(result *enterprisestatus.Result) string {
	parts := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		parts = append(parts, e.Code+": "+e.Message)
	}
	if len(parts) == 0 {
		return result.Action + " failed"
	}
	return result.Action + " failed: " + joinMessages(parts)
}

func runEnterpriseSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) error {
	goos := enterpriseunix.CurrentGOOS()
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if action != "status" && env.Geteuid() != 0 {
		return withExitCode(errors.New("run this command as root"), enterprisestatus.UnixExitFailure)
	}
	if err := checkLockWait(cmd, opts.lockWait); err != nil {
		return err
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	switch action {
	case "status":
		states, err := env.SecretStatus()
		if errors.Is(err, fs.ErrPermission) {
			// The credentials directory is root-only (or root and the
			// service account): a standard account cannot list it.
			return withExitCode(fmt.Errorf("listing the protected credentials requires administrator rights; run: sudo %s enterprise secret status",
				filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")), enterprisestatus.UnixExitFailure)
		}
		if err != nil {
			return withExitCode(err, enterprisestatus.UnixExitFailure)
		}
		if opts.json {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"schema_version": 1, "secrets": states})
		}
		if len(states) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "no protected credentials")
		}
		for _, state := range states {
			fmt.Fprintf(cmd.OutOrStdout(), "%-32s sha256:%s… mode %s modified %s\n", state.Name, state.SHA256Prefix, state.Mode, state.ModifiedAt)
		}
		return nil
	}
	// Argument errors are refused like a malformed flag, with the usage line
	// and exit 2, before the value is read or the lifecycle lock is taken
	// (GAP-2146, GAP-2147).
	if !managed.ValidCredentialName(opts.name) {
		return lifecycleFlagError(cmd, fmt.Errorf("--name takes lowercase letters, digits and dashes, not %q", opts.name))
	}
	if action == "set" && opts.fromStdin == (opts.fromFile != "") {
		return lifecycleFlagError(cmd, errors.New("pass exactly one of --from-stdin or --from-file"))
	}
	var mutate func(context.Context) error
	existed := false
	switch action {
	case "set":
		var source io.Reader = cmd.InOrStdin()
		if opts.fromFile != "" {
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			defer file.Close()
			source = file
		}
		value, err := enterpriseunix.ReadSecretValue(source)
		if err != nil {
			return withExitCode(err, enterprisestatus.UnixExitInvalidArgs)
		}
		mutate = func(ctx context.Context) error {
			// An identical value is not rewritten, so the output can say
			// the credential already holds it (GAP-2373).
			stored, readErr := os.ReadFile(filepath.Join(env.P(env.Layout.SecretsDir), opts.name))
			if existed = readErr == nil && subtle.ConstantTimeCompare(stored, value) == 1; existed {
				return nil
			}
			return env.WriteSecret(ctx, opts.name, value)
		}
	case "remove":
		mutate = func(context.Context) error {
			_, statErr := os.Lstat(filepath.Join(env.P(env.Layout.SecretsDir), opts.name))
			existed = statErr == nil
			return env.RemoveSecret(opts.name)
		}
	}
	// Write and apply under one lifecycle lock. The apply watcher the write
	// wakes then finds the change already applied instead of racing it.
	result := enterpriseunix.Run(cmd.Context(), env, enterpriseunix.Options{Action: enterpriseunix.ActionEnsure, Reason: "secret", Mutate: mutate})
	if !opts.json {
		result = describeSecretChange(result, action, opts.name, existed)
	}
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	return lifecycleFailure(result, opts.json, "")
}

// describeSecretChange labels a secret set or remove result with the command
// the administrator typed and the credential it changed. Both printed the
// same "✓ ensure: done" block before, so the two opposite actions could not
// be told apart (GAP-2305). The JSON document keeps action "ensure". For
// set, existed reports that the credential already held this exact value.
func describeSecretChange(result *enterprisestatus.Result, action, name string, existed bool) *enterprisestatus.Result {
	shown := *result
	shown.Action = "secret " + action
	if !result.OK {
		return &shown
	}
	change := "stored credential " + name
	if action == "set" && existed {
		change = "credential " + name + " already holds this value; not rewritten"
	} else if action == "set" && result.Noop && result.NoopReason == "up_to_date" {
		// The value was written, so "nothing to do" would be wrong even
		// when the apply found nothing else to change (GAP-2373).
		shown.Noop, shown.NoopReason = false, ""
	}
	if action == "remove" {
		change = "removed credential " + name
		if !existed {
			change = "credential " + name + " was not stored; nothing to remove"
		}
	}
	if result.Noop && result.NoopReason == "not_installed" {
		// Stored before the first install, a documented step: the
		// headline says the change was stored, not "nothing to do" with a
		// warning (GAP-2353). The JSON document keeps the noop and warning.
		shown.Noop, shown.NoopReason = false, ""
		shown.Warnings = nil
		for _, warning := range result.Warnings {
			if warning.Code != "not_installed" {
				shown.Warnings = append(shown.Warnings, warning)
			}
		}
		change += "; DefenseClaw enterprise is not installed yet, so the first install applies it"
	}
	shown.Changes = append([]string{change}, result.Changes...)
	return &shown
}
