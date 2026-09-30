// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookForeignGuardSummaryDirTrusted validates the directory that holds the
// public machine policy summary. Replaceable in tests.
var hookForeignGuardSummaryDirTrusted = platformHookForeignGuardSummaryDirTrusted

// hookForeignGuardStandaloneRegistered reports the administrator-only
// standalone registration (on Windows the HKLM marker the elevated
// standalone lifecycle publishes; see managedHostWindowsStandalone).
// Replaceable in tests.
var hookForeignGuardStandaloneRegistered = func() bool {
	_, registered := managedHostWindowsStandalone()
	return registered
}

// applyHostEnterpriseForeignHookGuard is the hook command's entry to the
// foreign-hook guard. The guard reads a fixed summary path on every hook
// invocation, whatever the profile, and fails closed on a summary it cannot
// trust. On Windows that path is under %ProgramData%\Cisco, where a standard
// user can create folders on hosts that keep the stock ProgramData
// inheritance (Secure Client hosts and unmanaged hosts). Only a summary
// directory an administrator wrote, or the administrator-only standalone
// registration, belongs to a standalone deployment, so the guard runs only on
// a host that carries one of them. On every other host the guard is a no-op,
// as it was before the guard existed: a file or folder a standard user
// plants at the summary path must not make every user's hooks fail closed.
func applyHostEnterpriseForeignHookGuard(opts *hookexec.Options) {
	if !hookForeignGuardHostEligible() {
		return
	}
	applyEnterpriseForeignHookGuard(opts)
}

// hookForeignGuardHostEligible reports whether this host carries an
// administrator-written summary directory, or failing that the
// administrator-only standalone registration. A standard user cannot create
// or replace either, so it cannot use this check to switch the guard off on
// a standalone host. The registration covers a standalone host whose summary
// directory fails its check for a reason no standard user controls (drifted
// ACLs, an unreadable security descriptor, a drive the mount check refuses):
// the guard still runs there and fails closed on a summary it cannot trust,
// as it did before this gate. Secure Client never writes the registration,
// and it is read only when the directory check fails.
func hookForeignGuardHostEligible() bool {
	path, ok := hookForeignGuardSummaryPath()
	if !ok || strings.TrimSpace(path) == "" {
		return false
	}
	if hookForeignGuardSummaryDirTrusted(filepath.Dir(path)) == nil {
		return true
	}
	return hookForeignGuardStandaloneRegistered()
}
