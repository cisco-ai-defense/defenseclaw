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
	"bytes"
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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// newUnixLifecycleEnv is a seam for CLI tests.
var newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
	env, err := enterpriseunix.NewEnv(goos, appVersion)
	if env != nil {
		// Every changing run verifies signed bundles (the apply trigger
		// processes the bundle inbox).
		env.BundleDigester = bundleDigester
	}
	return env, err
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
	var interrupted <-chan struct{}
	switch action {
	case enterpriseunix.ActionRotateCredentials:
		var stop func()
		ctx, stop = settleInterruptedRotation(ctx, cmd.ErrOrStderr(), platform)
		defer stop()
	case enterpriseunix.ActionStatus, enterpriseunix.ActionVerify:
		// Read only: a signal stops them at once.
	default:
		var stop func()
		interrupted, stop = settleInterruptedLifecycle(cmd.ErrOrStderr(), "enterprise "+platform+" "+action, platform)
		defer stop()
	}
	result := enterpriseunix.Run(ctx, env, enterpriseunix.Options{
		Interrupted:        interrupted,
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
	if lifecycleResultHasError(result, "not_root") {
		reportManagedCommandRefusal("enterprise "+platform+" "+action, "not_root")
	}
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

// settleInterruptedLifecycle makes the first SIGTERM or interrupt of a
// changing lifecycle run (systemd stopping the apply trigger, an MDM
// timeout, Ctrl+C) ask the run to stop at its next safe point: the
// transaction finishes the step it is in, rolls back or completes, and the
// command prints its result. It used to die mid-step with no result, and a
// later run recovered the transaction (I-1317). A second signal exits at
// once; the next lifecycle run recovers what it left.
func settleInterruptedLifecycle(w io.Writer, command, platform string) (<-chan struct{}, func()) {
	interrupted := make(chan struct{})
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			fmt.Fprintf(w, "\n%s was interrupted; finishing the current step and restoring the previous deployment if the change is not committed yet. Interrupt again to stop at once.\n", command)
			close(interrupted)
		case <-done:
			return
		}
		select {
		case sig := <-signals:
			fmt.Fprintf(w, "\n%s stopped in the middle of a step; run `enterprise %s ensure` as root to restore the previous deployment or finish the change.\n", command, platform)
			code := 130
			if sig == syscall.SIGTERM {
				code = 143
			}
			os.Exit(code)
		case <-done:
		}
	}()
	return interrupted, func() {
		signal.Stop(signals)
		close(done)
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
	// repair is not the next step (GAP-2246). Nor is it for a gateway whose
	// config the installed binary refuses: repair applies the same config
	// again, and the config_refused error above names the fix.
	if repairCommand != "" && result.Installed && !lifecycleResultHasError(result, "lifecycle_busy") &&
		!lifecycleResultHasError(result, "config_refused") && !repairCannotFixProblems(result) &&
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
		result.PreserveNotRootDeploymentState = secureClientHost()
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
	if result.Action == enterpriseunix.ActionRotateCredentials && result.Noop && result.NoopReason == enterpriseunix.NoopNoCredentials {
		fmt.Fprintln(w, "  no enrolled user holds a DefenseClaw credential yet: hooks use the hook socket, and the guardian creates the per-user key when it first gives a user one (agent telemetry, an in-agent plugin or ACP)")
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
		enterprisestatus.WriteDestinations(w, result.Destinations)
	}
	// The policy the lifecycle left in place (absent under Secure Client):
	// an administrator reading the text must see the generation and digest.
	if result.Policy != nil {
		fmt.Fprintf(w, "  %s\n", result.PolicyLine())
	}
	if result.Bundle != nil && result.Bundle.SessionsRestartRequired != nil {
		enterprisestatus.WriteSessionEntries(w, *result.Bundle.SessionsRestartRequired)
	}
	// A busy status checked nothing else, but still reports the recorded
	// deployment's version, as the docs say (GAP-2409).
	if result.Action == enterpriseunix.ActionStatus && result.Installed && lifecycleResultHasError(result, "lifecycle_busy") {
		fmt.Fprintf(w, "  installed=true version=%s\n", result.InstalledVersion)
	}
	return nil
}

// repairCannotFixProblems reports whether every error of result is one
// repair does not fix: a config problem (no connector enabled, a rejected
// config.yaml), whose line says to change config.yaml and run ensure
// (GAP-0265), or a file the administrator owns.
func repairCannotFixProblems(result *enterprisestatus.Result) bool {
	configProblems := map[string]bool{}
	for _, warning := range result.Warnings {
		if warning.Code == "no_connectors_enabled" || warning.Code == "config_rejected" {
			configProblems[warning.Message] = true
		}
	}
	for _, e := range result.Errors {
		// A file the administrator owns (ownership: verify_only) is fixed by
		// deploying the export the problem names; repair never writes it
		// (GAP-0918).
		if !configProblems[e.Message] && !strings.Contains(e.Message, "missing_defenseclaw_hooks:") {
			return false
		}
	}
	return len(result.Errors) > 0
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

func init() {
	// With --json every Linux and macOS secret verb prints one JSON
	// document on stdout, a flag error too (mgmt-agent-api GAP-0031).
	enterpriseSecretArgumentRefusal = func(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error) error {
		return reportUnixSecretFailure(cmd, action, opts, err, opts.json || secretArgsRequestJSON(secretRawArgs()))
	}
}

// reportUnixSecretFailure prints the secret-result failure document of a
// secret command that failed before the lifecycle ran.
func reportUnixSecretFailure(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error, asJSON bool) error {
	return reportSecretFailure(cmd, action, opts, err, asJSON, enterprisestatus.UnixExitFailure, enterprisestatus.UnixExitInvalidArgs)
}

// runEnterpriseSecret implements `enterprise secret` on Linux and macOS.
// set and remove print lifecycle result v2 once the lifecycle ran; a
// failure before it (argument, flag, privilege, value or read errors) prints
// the secret-result failure document with --json, never an empty stdout:
// an agent stopped while secret set read its stdin got only "credential is
// empty" on stderr (mgmt-agent-api GAP-0031).
func runEnterpriseSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) error {
	// The caller is taken before stdin is read: a parent that exits while
	// this command reads the value, or waits for the lock, stores nothing.
	caller := secretCallerPID()
	if action == "status" {
		if err := runUnixSecretStatus(cmd, opts); err != nil {
			return reportUnixSecretFailure(cmd, action, opts, err, opts.json)
		}
		return nil
	}
	result, existed, reservation, err := changeUnixSecret(cmd, action, opts, caller)
	defer func() { _ = reservation.Release() }()
	addWarning := func(warning enterprisebundle.Warning) {
		if err == nil && result != nil {
			result.AddWarning(warning.Code, warning.Message)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s\n", warning.Code, warning.Message)
		}
	}
	if recordErr := recordUnixSecretChange(reservation, action, opts.name, existed, result, err); recordErr != nil {
		addWarning(changeUnrecordedWarning(recordErr))
	}
	// A set of the stored value and the removal of an absent credential
	// record nothing: their reservation goes here, durably.
	if releaseErr := reservation.Release(); releaseErr != nil {
		addWarning(changeReleaseUnflushedWarning(releaseErr))
	}
	if err != nil {
		return reportUnixSecretFailure(cmd, action, opts, err, opts.json)
	}
	if !opts.json {
		result = describeSecretChange(result, action, opts.name, existed)
	}
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	return lifecycleFailure(result, opts.json, "")
}

// recordUnixSecretChange leaves the change event of a secret set or remove
// for the gateway: an applied change, a failed lifecycle run, or a refusal
// before it, through reservation once the command reserved room for it. A
// set of the stored value and the removal of an absent credential changed
// nothing and record nothing; a caller that is not root cannot record. The
// error is a change event that could not be written.
func recordUnixSecretChange(reservation *enterprisestatus.ChangeReservation, action, name string, existed bool, result *enterprisestatus.Result, err error) error {
	code, attempted := "", false
	switch {
	case err != nil:
		code = secretFailureCode(err, enterprisestatus.UnixExitInvalidArgs)
	case result != nil && len(result.Errors) > 0:
		// The lifecycle run that writes or removes the credential failed.
		code, attempted = result.Errors[0].Code, true
		err = errors.New(code)
	case result == nil:
		return nil
	}
	changed := (action == "set" && !existed) || (action == "remove" && existed)
	ev, ok := secretChangeEvent(action, name, changed, code, err, attempted)
	if !ok {
		return nil
	}
	if reservation != nil {
		return reservation.Write(ev)
	}
	env, envErr := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if envErr != nil {
		return envErr
	}
	if env.Geteuid() != 0 {
		return nil
	}
	return env.RecordChange(ev)
}

func runUnixSecretStatus(cmd *cobra.Command, opts *enterpriseSecretOptions) error {
	goos := enterpriseunix.CurrentGOOS()
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	states, err := env.SecretStatus()
	if errors.Is(err, fs.ErrPermission) {
		// The credentials directory is root-only (or root and the service
		// account): a standard account cannot list it.
		return secretFailed("not_root", enterprisestatus.UnixExitFailure, fmt.Errorf("listing the protected credentials requires administrator rights; run: sudo %s enterprise secret status",
			filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")))
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

// changeUnixSecret checks the arguments, reads the value, reserves room for
// the change event and runs the write or removal and the ensure under one
// lifecycle lock. An error is a failure before the lifecycle ran; the
// result can still be a failure. The caller writes the change event through
// the reservation and releases it.
func changeUnixSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, caller int) (*enterprisestatus.Result, bool, *enterprisestatus.ChangeReservation, error) {
	goos := enterpriseunix.CurrentGOOS()
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return nil, false, nil, withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if env.Geteuid() != 0 {
		return nil, false, nil, secretFailed("not_root", enterprisestatus.UnixExitFailure, errors.New("run this command as root"))
	}
	if err := checkLockWait(cmd, opts.lockWait); err != nil {
		return nil, false, nil, err
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	// Argument errors are refused like a malformed flag, with the usage line
	// and exit 2, before the value is read or the lifecycle lock is taken
	// (GAP-2146, GAP-2147).
	if !managed.ValidCredentialName(opts.name) {
		return nil, false, nil, lifecycleFlagError(cmd, fmt.Errorf("--name takes 1 to 63 lowercase letters, digits and dashes, starting with a letter or digit; not %q", opts.name))
	}
	if action == "set" && opts.fromStdin == (opts.fromFile != "") {
		return nil, false, nil, lifecycleFlagError(cmd, errors.New("pass exactly one of --from-stdin or --from-file"))
	}
	if err := secretTransactionArguments(opts); err != nil {
		return nil, false, nil, lifecycleFlagError(cmd, err)
	}
	var mutate func(context.Context) error
	existed := false
	switch action {
	case "set":
		var value []byte
		if opts.fromFile != "" {
			if err := enterpriseunix.TrustedSecretSource(opts.fromFile); err != nil {
				return nil, false, nil, withExitCode(err, enterprisestatus.UnixExitInvalidArgs)
			}
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return nil, false, nil, secretFailed(codeSecretChangeFailed, enterprisestatus.UnixExitFailure, err)
			}
			defer file.Close()
			if value, err = enterpriseunix.ReadSecretValue(file); err != nil {
				return nil, false, nil, withExitCode(err, enterprisestatus.UnixExitInvalidArgs)
			}
		} else if value, err = readUnixSecretStdin(cmd.InOrStdin(), caller); err != nil {
			return nil, false, nil, err
		}
		mutate = func(ctx context.Context) error {
			if err := secretCallerGone(caller, secretCallerPID()); err != nil {
				return err
			}
			// An identical value is not rewritten, so the output can say
			// the credential already holds it (GAP-2373).
			stored, readErr := os.ReadFile(filepath.Join(env.P(env.Layout.SecretsDir), opts.name))
			if err := checkSecretTransaction(opts.name, opts, stored, readErr == nil); err != nil {
				return err
			}
			if existed = readErr == nil && subtle.ConstantTimeCompare(stored, value) == 1; existed {
				return nil
			}
			// A value the signed bundle does not bind is not stored. A
			// credential that cannot be read counts as stored.
			replacing := readErr == nil || !errors.Is(readErr, fs.ErrNotExist)
			if err := checkSecretBinding(ctx, opts.name, value, opts.bundle, replacing); err != nil {
				return err
			}
			return env.WriteSecret(ctx, opts.name, value)
		}
	case "remove":
		mutate = func(context.Context) error {
			path := filepath.Join(env.P(env.Layout.SecretsDir), opts.name)
			if opts.undoRotation != "" {
				stored, readErr := os.ReadFile(path)
				if err := checkSecretTransaction(opts.name, opts, stored, readErr == nil); err != nil {
					return err
				}
			}
			_, statErr := os.Lstat(path)
			existed = statErr == nil
			return env.RemoveSecret(opts.name)
		}
	}
	// A change this device could not audit is not made: the spool must hold
	// room for its change event before the credential is written or
	// removed, until the event is written. A concurrent command cannot take
	// that room in between.
	reservation, err := env.ReserveChange(enterprisestatus.ChangeKindSecret, action, opts.name)
	if err != nil {
		return nil, false, nil, secretFailed(string(enterprisebundle.CodeStateInvalid), enterprisestatus.UnixExitFailure,
			fmt.Errorf("cannot record the credential change: %w", err))
	}
	// Write and apply under one lifecycle lock. The apply watcher the write
	// wakes then finds the change already applied instead of racing it.
	result := enterpriseunix.Run(cmd.Context(), env, enterpriseunix.Options{Action: enterpriseunix.ActionEnsure, Reason: "secret", Mutate: mutate})
	return result, existed, reservation, nil
}

// secretCallerPID is the parent of this process. A seam for tests.
var secretCallerPID = os.Getppid

// secretStdinWait bounds how long secret set waits for its value on stdin.
// A management agent writes the value and closes stdin right after it
// starts the command; a sender that stopped (SIGSTOP) or that left stdin
// open without writing hung the command forever (mgmt-agent-api GAP-0040).
var secretStdinWait = 60 * time.Second

// secretCallerSettle is how long secret set watches its parent after stdin
// ended without a complete line. A process that exits closes its end of the
// pipe before the kernel makes init the parent of its children (macOS shows
// it every time), so the end of stdin arrives while the parent still looks
// alive (mgmt-agent-api GAP-0040). A value ended by a newline does not wait.
var secretCallerSettle = time.Second

// secretCallerPoll is how often secret set looks at its parent while it
// waits for the value or for a parent that exited to show.
const secretCallerPoll = 10 * time.Millisecond

// errSecretSenderExited is the change_failed message of a secret set whose
// caller exited before it sent the whole value.
var errSecretSenderExited = errors.New("the process that started this command exited before it sent the credential, so the credential was not stored; run the command again")

// readUnixSecretStdin reads the value of secret set --from-stdin. It is
// change_failed (exit 1: nothing stored, the agent sends the value again in
// a new run) when the sender went away before it sent a complete value:
// stdin ended without a complete line, or failed, and the parent exited;
// the parent exited while stdin stayed open; or no value ended within
// secretStdinWait. A value that ended (with or without a newline) while the
// parent stayed is checked as given: empty, multi-line or oversized is
// invalid_arguments (exit 2), as is a read error.
func readUnixSecretStdin(source io.Reader, caller int) ([]byte, error) {
	type delivery struct {
		data []byte
		err  error
	}
	done := make(chan delivery, 1)
	go func() {
		// Left blocked on a stdin that never ends: the command exits
		// after it reports the timeout.
		data, err := enterpriseunix.ReadSecretBytes(source)
		done <- delivery{data, err}
	}()
	deadline := time.NewTimer(secretStdinWait)
	defer deadline.Stop()
	poll := time.NewTicker(secretCallerPoll)
	defer poll.Stop()
	var got delivery
	for waiting := true; waiting; {
		select {
		case got = <-done:
			waiting = false
		case <-poll.C:
			// A process the agent started can hold stdin open after the
			// agent exited.
			if secretCallerPID() != caller {
				return nil, secretFailed(codeSecretChangeFailed, enterprisestatus.UnixExitFailure, errSecretSenderExited)
			}
		case <-deadline.C:
			return nil, secretFailed(codeSecretChangeFailed, enterprisestatus.UnixExitFailure,
				fmt.Errorf("no credential arrived on stdin within %s (the process that started this command stopped sending and did not close stdin), so the credential was not stored; run the command again, write the value and close stdin", secretStdinWait))
		}
	}
	if got.err != nil || !bytes.HasSuffix(got.data, []byte("\n")) {
		if secretCallerExitsWithin(caller, secretCallerSettle) {
			return nil, secretFailed(codeSecretChangeFailed, enterprisestatus.UnixExitFailure, errSecretSenderExited)
		}
	}
	if got.err != nil {
		return nil, withExitCode(got.err, enterprisestatus.UnixExitInvalidArgs)
	}
	value, err := enterpriseunix.ParseSecretValue(got.data)
	if err != nil {
		return nil, withExitCode(err, enterprisestatus.UnixExitInvalidArgs)
	}
	return value, nil
}

// secretCallerExitsWithin reports whether the parent of this process stops
// being caller within settle.
func secretCallerExitsWithin(caller int, settle time.Duration) bool {
	deadline := time.Now().Add(settle)
	for {
		if secretCallerPID() != caller {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(secretCallerPoll)
	}
}

// secretCallerGone refuses to store a credential once the process that ran
// `secret set` has exited while the command waited for the lifecycle lock:
// an MDM agent that killed its wrapper reported the run as failed, and the
// orphaned command stored the key minutes later anyway (GAP-0632).
func secretCallerGone(started, now int) error {
	if started == now {
		return nil
	}
	return errors.New("the process that started this command exited while it waited for the lifecycle lock, so the credential was not stored; run the command again")
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
