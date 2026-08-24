// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package ipc implements the local UDS gRPC server that AVC (Cisco
// Secure Client) consumes to observe DefenseClaw health, aggregate
// stats, and user-visible notifications. See
// proto/defenseclaw/secureclient/v1 for the wire contract.
package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// SocketFileName is the fixed filename component of the socket path
// across all deployment modes. Directory placement varies by mode —
// see ResolveSocketPath.
const SocketFileName = "defenseclaw_ipc.sock"

// SocketEnvVar names the environment variable that overrides all
// other resolution rules. Intended for test rigs and AVC development
// where the operator needs to point clients at a scratch socket.
const SocketEnvVar = "DEFENSECLAW_IPC_SOCKET"

// Default mode ceilings by deployment. Managed enterprise keeps the
// socket at group-writable-only (root:staff 0660 on macOS, chown
// applied at bind time in internal/ipc/server.go). Unmanaged/dev
// stays owner-only because daemon and client run as the same
// principal. The managed_enterprise ceiling is 0660 — anything
// wider is refused at server start so an operator override cannot
// re-open the world-writable path.
const (
	defaultManagedSocketMode   os.FileMode = 0o660
	defaultUnmanagedSocketMode os.FileMode = 0o600
)

// ResolveSocketPath returns the UDS path derived from (in priority
// order): explicit config, environment variable, or a deployment-mode
// default. See docs/ipc.md and internal/ipc/paths.go for the full
// resolution rules.
//
//  1. cfg.Managed.SocketPath (verbatim)
//  2. $DEFENSECLAW_IPC_SOCKET (dev / test rigs only)
//  3. managed_enterprise → resolveManagedIPCSocketPath(cfg):
//     - linux/darwin: filepath.Join(filepath.Dir(cfg.DataDir),
//     "ipc", SocketFileName)
//     - windows:      filepath.Join(<TrustedProgramData>, "Cisco",
//     "Cisco Secure Client", "DefenseClaw", "ipc",
//     SocketFileName). See spec 004 REQ-02. Returns "" when
//     TrustedProgramData resolution fails; the caller's
//     ResolveSocketPath empty-check turns that into a
//     distinguishable "ipc: resolve socket path: empty"
//     server-start error rather than a fall-through to a
//     per-user path.
//  4. otherwise → filepath.Join(cfg.DataDir, "ipc", SocketFileName)
//
// The env override is intentionally ignored in managed_enterprise so
// a systemd unit drop-in or launchd env inheritance cannot redirect
// the enterprise-owned socket path. On linux/darwin, operators who
// need to move the socket in production may set cfg.Managed.SocketPath
// explicitly and validateManagedSocketPathOverride will honor a
// per-platform-trusted parent. On Windows the socket path is fixed to
// <TrustedProgramData>/Cisco/Cisco Secure Client/DefenseClaw/ipc/
// SocketFileName: validateWindowsSocketPathOverride only accepts a
// byte-identical override, so cfg.Managed.SocketPath is effectively
// non-configurable there. See internal/ipc/server_windows.go.
//
// Never returns an error: rule 4 always produces a value (rule 3 may
// return "" on Windows when the TrustedProgramData registry lookup
// fails — the server refuses to start in that case).
func ResolveSocketPath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if p := cfg.Managed.SocketPath; p != "" {
		return p
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if p := os.Getenv(SocketEnvVar); p != "" {
			return p
		}
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return resolveManagedIPCSocketPath(cfg)
	}
	return filepath.Join(cfg.DataDir, "ipc", SocketFileName)
}

// ResolveSocketMode returns the octal socket permission derived from
// cfg.Managed.SocketMode (when set) or the deployment default. The
// returned mode is validated against the per-mode ceiling: managed
// installs allow up to 0o666 (peer-cred gates access), unmanaged
// installs allow up to 0o600 (owner-only).
//
// A wider-than-ceiling value returns an error rather than being
// silently narrowed — the operator has misconfigured something and
// should see it.
func ResolveSocketMode(cfg *config.Config) (os.FileMode, error) {
	if cfg == nil {
		return 0, fmt.Errorf("ipc: resolve socket mode: nil config")
	}
	ceiling := defaultUnmanagedSocketMode
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		ceiling = defaultManagedSocketMode
	}
	explicit := cfg.Managed.SocketMode
	if explicit == "" {
		return ceiling, nil
	}
	parsed, err := strconv.ParseUint(explicit, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("ipc: parse socket mode %q as octal: %w", explicit, err)
	}
	mode := os.FileMode(parsed) & os.ModePerm
	if mode > ceiling {
		return 0, fmt.Errorf("ipc: socket_mode %#o exceeds ceiling %#o for this deployment", mode, ceiling)
	}
	return mode, nil
}
