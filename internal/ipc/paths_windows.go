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
// TrustedProgramFiles that holds the DefenseClaw UDS socket. The
// literal is fixed by the AVC integration contract: Cisco Secure
// Client's Windows GUI dials this exact path. Changing it requires
// a coordinated change with the AVC packaging team.
//
// The final socket path is
// `<TrustedProgramFiles>\Cisco\Cisco Secure Client\DefenseClaw\ipc\defenseclaw_ipc.sock`.
//
// Historical note: earlier builds placed this under TrustedProgramData
// (ProgramData is the Windows convention for mutable machine state).
// The AVC release-26.8.4 integration moved it under TrustedProgramFiles
// so both peers dial the same known-root prefix. The virtual service
// SID granted DACL rights on this directory during install can bind /
// unlink the socket under Program Files just as under ProgramData.
//
// See spec 004 REQ-02 and parity plan §4.2 C1.
var windowsManagedIPCRelativeDir = filepath.Join(
	"Cisco", "Cisco Secure Client", "DefenseClaw", "ipc",
)

// resolveManagedIPCSocketPath returns the managed-enterprise UDS
// socket path on Windows. Resolves `TrustedProgramFiles` through the
// same fail-closed registry path env_config_windows.go uses so the
// user-supplied `%ProgramFiles%` env cannot redirect the socket
// off-disk or into a per-user profile.
//
// Returns "" when TrustedProgramFiles resolution fails; the caller
// (ResolveSocketPath in paths.go) turns that into a distinguishable
// "ipc: resolve socket path: empty" server-start error rather than
// falling back to a per-user path.
//
// Spec 004 REQ-02.
func resolveManagedIPCSocketPath(cfg *config.Config) string {
	_ = cfg // reserved: a future spec may consult cfg.Managed for override plumbing
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil || programFiles == "" {
		return ""
	}
	return filepath.Join(programFiles, windowsManagedIPCRelativeDir, SocketFileName)
}
