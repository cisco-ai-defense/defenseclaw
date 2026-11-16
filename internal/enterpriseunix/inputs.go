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

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A transaction reads config.yaml and the protected credentials once, when
// it plans. Configuration management writes them in place and relies on the
// apply trigger, so a write can land while another run holds the lifecycle
// lock, and the apply trigger is stopped for most of a transaction. The
// transaction therefore never writes config.yaml bytes it read from the
// installed file (desiredFile.KeepContent), and once it has committed it
// compares the inputs with what it planned: a change is applied by a
// follow-up transaction in the same run, before the lock is released. After
// a failed transaction the apply trigger is started instead, so the change
// is applied once this run ends.
const (
	codeInputChanged = "input_changed"
	// maxInputFollowUps bounds the follow-up transactions of one run.
	maxInputFollowUps = 3
	// A failed run that is the systemd apply trigger itself has it started
	// again by a transient timer (scheduleApplyRetry): at most
	// maxApplyRetries times for one config.yaml, the first after
	// applyRetryDelay and each next one after twice the delay before. The
	// count is kept in applyRetryName in the lifecycle directory.
	maxApplyRetries = 3
	applyRetryDelay = 30 * time.Second
	applyRetryName  = "apply-retry.json"
	unitApplyRetry  = "defenseclaw-enterprise-apply-retry"
)

// inputsChanged reports whether config.yaml or the protected credentials
// differ from what the last transaction of this run planned.
func (l *lifecycle) inputsChanged() bool {
	env, r, planned := l.env, l.result, l.planned
	if planned == nil {
		return false
	}
	if _, secretsSHA, err := env.listSecrets(); err == nil && secretsSHA != planned.secretsSHA {
		return true
	}
	current, err := sha256File(env.P(env.Layout.ConfigPath))
	if err != nil {
		return false
	}
	if len(r.Errors) > 0 && !planned.configFromInstalled {
		// A failed --config run put the previous deployment's config.yaml
		// back. Any other config.yaml on disk now is a newer input: one
		// another writer put in place during the run (put back after the
		// restart), or one written after the restore (GAP-1379).
		return l.rollbackConfigSHA != "" && planned.appliedConfigSHA != "" && current != planned.appliedConfigSHA
	}
	if len(r.Errors) > 0 && hasMessageCode(r.Warnings, codeConfigReverted) {
		// A rejected in-place edit was reverted on purpose; the restored
		// last applied config is not a newer push to apply. Any other
		// config.yaml is one (revertRejectedConfig puts one written during
		// the run back), also the rejected bytes written again after the
		// revert: configuration management retrying the same desired config
		// (GAP-1412). The rejected bytes still in place because the revert
		// failed are not.
		committed, err := readBounded(env.committedConfigPath(), maxInputBytes)
		if err != nil || current == sha256Bytes(committed) {
			return false
		}
		return current != planned.configSHA || writtenSince(env.P(env.Layout.ConfigPath), planned.revertedConfig)
	}
	return current != planned.configSHA
}

// settleInputChanges applies input changes made while a transaction ran;
// code is the transaction's exit code and the result's.
func (l *lifecycle) settleInputChanges(ctx context.Context, code int) int {
	env, r := l.env, l.result
	for pass := 0; l.inputsChanged(); pass++ {
		// A stopped run starts no follow-up; the apply trigger runs it.
		if len(r.Errors) > 0 || pass == maxInputFollowUps || l.interrupted() {
			l.retriggerApply(ctx)
			return code
		}
		record, err := env.loadDeployment()
		if err != nil || record == nil {
			return code
		}
		r.AddWarning(codeInputChanged, "config.yaml or a protected credential changed while this run applied the previous version; applied the change in a follow-up transaction")
		next := &lifecycle{env: env, opts: Options{Action: ActionEnsure, Reason: codeInputChanged, NoStart: record.NoStart, Interrupted: l.opts.Interrupted}, result: r}
		// In bundle mode the follow-up applies the config of the current
		// bundle again, never an in-place edit of config.yaml.
		if !next.useCurrentBundleConfig() {
			return code
		}
		code = next.apply(ctx, record)
		l.planned = next.planned
	}
	if len(r.Errors) == 0 {
		env.clearApplyRetries()
	}
	return code
}

// retriggerApply makes the apply trigger run ensure once this run releases
// the lifecycle lock, or tells the administrator to when this run is the
// apply trigger itself.
func (l *lifecycle) retriggerApply(ctx context.Context) {
	env, r := l.env, l.result
	message := "config.yaml or a protected credential changed while this run held the lifecycle lock and is not applied yet"
	if env.SelfUnit == "" {
		var err error
		if env.GOOS == "darwin" {
			_, err = env.Runner.Run(ctx, "launchctl", "kickstart", "system/"+labelApply)
		} else {
			_, err = env.Runner.Run(ctx, "systemctl", "start", "--no-block", unitApplyService)
		}
		if err == nil {
			r.AddWarning(codeInputChanged, message+"; the apply trigger runs ensure once this run ends")
			return
		}
	} else if env.GOOS != "darwin" && l.scheduleApplyRetry(ctx, message) {
		return
	}
	r.AddWarning(codeInputChanged, message+"; run `"+env.lifecycleCommand("ensure")+"` to apply it")
}

// applyRetries counts the deferred re-runs scheduled for one config.yaml.
type applyRetries struct {
	ConfigSHA256 string `json:"config_sha256"`
	Attempts     int    `json:"attempts"`
}

func (e *Env) applyRetryPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), applyRetryName)
}

// clearApplyRetries resets the count once a run applied or confirmed the
// installed config.
func (e *Env) clearApplyRetries() {
	_ = removeFile(e.applyRetryPath())
}

// scheduleApplyRetry makes the apply trigger run ensure again after this
// run, which is that trigger, has ended (GAP-1412). systemd merges a start
// of the oneshot it is still running into the running job, and kills what
// the unit started when it ends, so a transient timer outside the unit
// starts it after a delay. A config.yaml whose runs keep failing stops at
// maxApplyRetries, and the result says so; the count starts again for a
// different config.yaml and after a healthy run. It reports false when no
// re-run was scheduled and the caller asks for a manual ensure.
func (l *lifecycle) scheduleApplyRetry(ctx context.Context, message string) bool {
	env, r := l.env, l.result
	sha, err := sha256File(env.P(env.Layout.ConfigPath))
	if err != nil {
		return false
	}
	var state applyRetries
	if raw, err := readBounded(env.applyRetryPath(), maxInputBytes); err == nil {
		_ = json.Unmarshal(raw, &state)
	}
	if state.ConfigSHA256 != sha || state.Attempts < 0 {
		// A different config.yaml starts a new count.
		env.clearApplyRetries()
		state = applyRetries{ConfigSHA256: sha}
	}
	if state.Attempts >= maxApplyRetries {
		r.AddWarning(codeInputChanged, fmt.Sprintf("%s; retry limit reached: the apply trigger ran ensure again %d times for this config.yaml and it is still not applied, run `%s` to apply it",
			message, maxApplyRetries, env.lifecycleCommand("ensure")))
		return true
	}
	delay := applyRetryDelay << state.Attempts
	if _, err := env.Runner.Run(ctx, "systemd-run", "--quiet", "--collect", "--unit="+unitApplyRetry,
		fmt.Sprintf("--on-active=%ds", int(delay/time.Second)), "--timer-property=AccuracySec=1s", "--timer-property=RemainAfterElapse=no",
		"systemctl", "start", "--no-block", unitApplyService); err != nil {
		// Nothing is scheduled, so the count stays as it was (GAP-1412).
		return false
	}
	state.Attempts++
	data, err := json.Marshal(state)
	if err == nil {
		err = env.writeFileAtomic(env.applyRetryPath(), append(data, '\n'), 0o600, rootOwner())
	}
	if err != nil {
		// An uncounted re-run would not be bounded.
		_, _ = env.Runner.Run(ctx, "systemctl", "stop", unitApplyRetry+".timer")
		return false
	}
	r.AddWarning(codeInputChanged, fmt.Sprintf("%s; the apply trigger runs ensure again in %s (retry %d of %d)", message, delay, state.Attempts, maxApplyRetries))
	return true
}

// writtenSince reports whether the file at path was written after it was
// in the state before describes; a nil before is never written since.
func writtenSince(path string, before os.FileInfo) bool {
	if before == nil {
		return false
	}
	now, err := os.Stat(path)
	return err == nil && (!os.SameFile(before, now) || !now.ModTime().Equal(before.ModTime()) || now.Size() != before.Size())
}

func hasMessageCode(messages []enterprisestatus.Message, code string) bool {
	for _, message := range messages {
		if message.Code == code {
			return true
		}
	}
	return false
}
