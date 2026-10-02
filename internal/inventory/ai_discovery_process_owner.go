// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os/user"
	"runtime"
)

// CurrentProcessOwner names the account (user name and uid) whose processes
// a per-user, unmanaged install reports. Such an install belongs to one
// account, so other accounts' agents, PIDs and command lines stay out of its
// inventory and telemetry (GAP-1105, GAP-1194). Both values are empty on
// Windows, which keeps its own process attribution, and when the account
// cannot be resolved.
func CurrentProcessOwner() (name, uid string) {
	if runtime.GOOS == "windows" {
		return "", ""
	}
	current, err := user.Current()
	if err != nil {
		return "", ""
	}
	return current.Username, current.Uid
}

// perUserProcessOwners is the processOwners filter of a per-user install, or
// nil when every visible process is in scope (managed and standalone
// enterprise, per-user scans, Windows).
func perUserProcessOwners(opts AIDiscoveryOptions) map[string]bool {
	if opts.ManagedEnterprise || opts.StandaloneEnterprise || opts.UserScanDir != "" {
		return nil
	}
	name, uid := CurrentProcessOwner()
	owners := map[string]bool{}
	for _, owner := range []string{name, uid} {
		if owner != "" {
			owners[owner] = true
		}
	}
	if len(owners) == 0 {
		return nil
	}
	return owners
}
