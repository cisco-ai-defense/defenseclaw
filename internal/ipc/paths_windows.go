// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsManagedIPCRelativeDir is the subpath under
// TrustedProgramData that holds the DefenseClaw UDS socket. The
// literal is fixed by the AVC integration contract: Cisco Secure
// Client's Windows GUI dials this exact path. Changing it requires
// a coordinated change with the AVC packaging team.
//
// The final socket path is
// `<TrustedProgramData>\Cisco\Cisco Secure Client\DefenseClaw\ipc\defenseclaw_ipc.sock`.
//
// See spec 004 REQ-02 and parity plan §4.2 C1.
var windowsManagedIPCRelativeDir = filepath.Join(
	"Cisco", "Cisco Secure Client", "DefenseClaw", "ipc",
)

// resolveManagedIPCSocketPath returns the managed-enterprise UDS
// socket path on Windows. Resolves `TrustedProgramData` through the
// same fail-closed registry path env_config_windows.go uses so the
// user-supplied `%ProgramData%` env cannot redirect the socket
// off-disk or into a per-user profile.
//
// Returns "" when TrustedProgramData resolution fails; the caller
// (ResolveSocketPath in paths.go) turns that into a distinguishable
// "ipc: resolve socket path: empty" server-start error rather than
// falling back to a per-user path.
//
// Spec 004 REQ-02.
func resolveManagedIPCSocketPath(cfg *config.Config) string {
	_ = cfg // reserved: a future spec may consult cfg.Managed for override plumbing
	programData, err := winpath.TrustedProgramData()
	if err != nil || programData == "" {
		return ""
	}
	return filepath.Join(programData, windowsManagedIPCRelativeDir, SocketFileName)
}
