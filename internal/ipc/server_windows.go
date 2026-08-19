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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// windowsSocketParentDirMode is the mode passed to os.MkdirAll for
// the socket's parent directory. Windows os.Chmod respects only the
// read-only bit, so this constant primarily documents intent — the
// authoritative access control is the DACL applied by
// applyBaselineIPCACL below.
const windowsSocketParentDirMode = os.FileMode(0o750)

// bindListenerForOS is the Windows bind block for the spec 004
// initial-cut deferred-auth IPC surface. Differences from
// server_unix.go's sibling:
//
//   - Skips os.Chmod on the socket file (Windows Chmod only touches
//     the read-only bit — Unix mode bits don't map to Windows DACLs).
//   - Skips os.Chown / staff-GID handling (Windows has no uid/gid).
//   - Applies a four-ACE baseline hygiene DACL via
//     applyBaselineIPCACL at BOTH the parent directory and the
//     socket file, with SE_DACL_PROTECTED so ancestor policy on
//     ProgramData cannot silently over-permit (spec 004 REQ-03
//     through REQ-05).
//
// Returns the raw net.Listener; the caller wraps it in the codesign
// validating listener (a passthrough on Windows — the Windows
// codesign validator in peerauth_windows.go returns the inner
// listener verbatim under the initial-cut posture).
func (s *Server) bindListenerForOS(ctx context.Context) (net.Listener, error) {
	// Refuse an operator override that points the socket at a
	// pre-existing path outside our dedicated dir. Applying
	// applyBaselineIPCACL to a shared directory would REPLACE the
	// caller's original DACL — including any ACEs Cisco Secure
	// Client or an unrelated installer relies on. See CR
	// spec-004:PRRT_kwDORuAK-s6ankzx.
	if err := validateWindowsSocketPathOverride(s.socketPath); err != nil {
		return nil, err
	}

	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, windowsSocketParentDirMode); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	// Directory gets the traverse+list-only Authenticated Users ACE.
	// FILE_ADD_FILE is deliberately refused so an auth-user cannot
	// pre-create a decoy at the socket path while the daemon is
	// stopped (CR spec-004:PRRT_kwDORuAK-s6ankzk).
	if err := applyBaselineIPCACL(dir, aclObjectDirectory); err != nil {
		return nil, err
	}

	// Best-effort remove of a stale socket file from a previous run
	// (matches the unix path — spec 004 REQ-20 bind-only-once).
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: remove stale socket %s: %w", s.socketPath, err)
	}

	lc := &net.ListenConfig{}
	inner, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		// A clearly-Windows-old-version error (WSAEAFNOSUPPORT or
		// similar) surfaces here; the wrapping preserves the OS
		// message so a triage path can distinguish "AF_UNIX not
		// supported" from a permission failure.
		return nil, fmt.Errorf("ipc: listen unix %s: %w", s.socketPath, err)
	}
	// Socket file gets the read+write Authenticated Users ACE —
	// enough for connect() + gRPC handshake, no WRITE_DAC.
	if err := applyBaselineIPCACL(s.socketPath, aclObjectSocketFile); err != nil {
		_ = inner.Close()
		return nil, err
	}
	return inner, nil
}

// validateWindowsSocketPathOverride refuses an operator override
// (cfg.Managed.SocketPath) that would cause applyBaselineIPCACL to
// rewrite the DACL of a shared or user-visible directory. Enforces:
//
//  1. Absolute path, no relative traversal.
//  2. Basename equals SocketFileName (defenseclaw_ipc.sock) — refuses
//     an override that points at a shared directory's existing file.
//  3. Parent directory basename is "ipc" — refuses an override that
//     would target ancestor policy at a directory shared with
//     unrelated files.
//
// Together these prevent an operator or an env-var-injected override
// from re-flagging an arbitrary path as the IPC socket, since
// applyBaselineIPCACL rewrites (with SE_DACL_PROTECTED) the DACL of
// the parent directory it targets. The dedicated default path
// (`<TrustedProgramData>\Cisco\...\DefenseClaw\ipc\defenseclaw_ipc.sock`)
// trivially satisfies all three checks; a scratch-dir override for
// CI still passes as long as it follows the shape.
func validateWindowsSocketPathOverride(socketPath string) error {
	if socketPath == "" {
		return fmt.Errorf("ipc: socket path is empty")
	}
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("ipc: socket path override must be absolute: %s", socketPath)
	}
	clean := filepath.Clean(socketPath)
	if filepath.Base(clean) != SocketFileName {
		return fmt.Errorf("ipc: socket path override must end in %q (got %s)", SocketFileName, clean)
	}
	parent := filepath.Dir(clean)
	if filepath.Base(parent) != "ipc" {
		return fmt.Errorf("ipc: socket path override must live under an 'ipc' directory (got parent %s)", parent)
	}
	return nil
}
