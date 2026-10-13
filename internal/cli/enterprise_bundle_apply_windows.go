// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// runEnterpriseBundleApply runs the Windows ensure with the bundle, as
// Setup /ensure BUNDLE= does. A Secure Client computer and a host that is
// not a standalone managed device are refused before anything is read.
func runEnterpriseBundleApply(cmd *cobra.Command, opts *bundleApplyOptions) error {
	if bundleSecureClient() {
		return bundleApplyRefused(cmd, opts.json, secureClientBundleRefusal())
	}
	if !bundleManagedDevice() {
		return bundleApplyRefused(cmd, opts.json, &enterprisebundle.Error{Code: enterprisebundle.CodeNotManaged,
			Detail: "this computer is not a standalone managed device; install the enterprise profile first"})
	}
	if opts.inbox || opts.bundle == "" {
		return bundleUsage("give --bundle; Windows takes bundles from Setup /ensure BUNDLE= or --bundle, not from an inbox")
	}
	bundle, err := filepath.Abs(opts.bundle)
	if err != nil {
		return bundleUsage("--bundle: %v", err)
	}
	return runWindowsEnterpriseLifecycle(cmd.Context(), cmd, "ensure", &windowsEnterpriseLifecycleOptions{
		bundlePath: bundle, profile: managed.ProfileStandalone, jsonOutput: opts.json,
	})
}
