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
		// A rejected in-place edit was reverted on purpose; only a
		// config.yaml that is neither the rejected edit nor the restored last
		// applied config is a newer push to apply (revertRejectedConfig puts
		// one written during the run back).
		committed, err := readBounded(env.committedConfigPath(), maxInputBytes)
		return err == nil && current != planned.configSHA && current != sha256Bytes(committed)
	}
	return current != planned.configSHA
}

// settleInputChanges applies input changes made while a transaction ran;
// code is the transaction's exit code and the result's.
func (l *lifecycle) settleInputChanges(ctx context.Context, code int) int {
	env, r := l.env, l.result
	for pass := 0; l.inputsChanged(); pass++ {
		if len(r.Errors) > 0 || pass == maxInputFollowUps {
			l.retriggerApply(ctx)
			return code
		}
		record, err := env.loadDeployment()
		if err != nil || record == nil {
			return code
		}
		r.AddWarning(codeInputChanged, "config.yaml or a protected credential changed while this run applied the previous version; applied the change in a follow-up transaction")
		next := &lifecycle{env: env, opts: Options{Action: ActionEnsure, Reason: codeInputChanged, NoStart: record.NoStart}, result: r}
		code = next.apply(ctx, record)
		l.planned = next.planned
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
	}
	r.AddWarning(codeInputChanged, message+"; run `"+env.lifecycleCommand("ensure")+"` to apply it")
}

func hasMessageCode(messages []enterprisestatus.Message, code string) bool {
	for _, message := range messages {
		if message.Code == code {
			return true
		}
	}
	return false
}
