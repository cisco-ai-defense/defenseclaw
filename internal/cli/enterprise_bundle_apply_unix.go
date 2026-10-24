// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// runEnterpriseBundleApply runs ensure with the bundle. A Secure Client
// computer and a host that is not a standalone managed device are refused
// before anything is read or changed.
func runEnterpriseBundleApply(cmd *cobra.Command, opts *bundleApplyOptions) error {
	if bundleSecureClient() {
		return bundleApplyRefused(cmd, opts.json, secureClientBundleRefusal())
	}
	if !bundleManagedDevice() {
		return bundleApplyRefused(cmd, opts.json, &enterprisebundle.Error{Code: enterprisebundle.CodeNotManaged,
			Detail: "this computer is not a standalone managed device; install the enterprise profile first"})
	}
	if (opts.bundle == "") == !opts.inbox {
		return bundleUsage("give --bundle or --inbox")
	}
	if err := checkLockWait(cmd, opts.lockWait); err != nil {
		return err
	}
	if err := checkDeliveryID(cmd, opts.deliveryID); err != nil {
		return err
	}
	bundle := opts.bundle
	if bundle != "" {
		abs, err := filepath.Abs(bundle)
		if err != nil {
			return bundleUsage("--bundle: %v", err)
		}
		bundle = abs
	}
	env, err := newUnixLifecycleEnv(runtime.GOOS)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	env.RefuseCapabilityLoss = opts.refuseCapabilityLoss
	env.DeferRestart = opts.deferRestart
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	applyOptions := unixBundleApplyOptions(opts, bundle)
	var stop func()
	applyOptions.Interrupted, stop = settleInterruptedLifecycle(cmd.ErrOrStderr(), "enterprise bundle apply", platform)
	defer stop()
	result := enterpriseunix.Run(cmd.Context(), env, applyOptions)
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	return lifecycleFailure(result, opts.json, "")
}

// unixBundleApplyOptions is the ensure run of `bundle apply` for the bundle
// at the absolute path bundle ("" with --inbox).
func unixBundleApplyOptions(opts *bundleApplyOptions, bundle string) enterpriseunix.Options {
	return enterpriseunix.Options{Action: enterpriseunix.ActionEnsure, Bundle: bundle, BundleInbox: opts.inbox,
		Reason: opts.reason, DeliveryID: opts.deliveryID}
}
