// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// resolveManagedIPCSocketPath returns the managed-enterprise UDS
// socket path on linux + darwin. Places the socket under
// filepath.Dir(cfg.DataDir)/ipc/ so the socket lives alongside — not
// inside — the daemon's per-run data area. Matches the historical
// macOS install layout at
// /opt/cisco/secureclient/defenseclaw/ipc/defenseclaw_ipc.sock.
//
// The Windows sibling in paths_windows.go returns the ProgramData
// path required by spec 004; both paths share ResolveSocketPath's
// unwrapping logic in paths.go.
func resolveManagedIPCSocketPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.DataDir), "ipc", SocketFileName)
}
