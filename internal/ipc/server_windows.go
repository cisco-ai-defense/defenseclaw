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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsSocketParentDirMode is the mode passed to os.MkdirAll for
// the socket's parent directory. Windows os.Chmod respects only the
// read-only bit, so this constant primarily documents intent — the
// authoritative access control is the DACL applied by
// applyBaselineIPCACL below.
const windowsSocketParentDirMode = os.FileMode(0o750)

// unsafeSocketOverrideEnv is a TEST-ONLY escape hatch that permits an
// override socket path outside the trusted ProgramData root. When set
// to "1", validateWindowsSocketPathOverride skips the trusted-root
// anchor and falls back to the shape check only. NEVER set on a
// production install: under the initial-cut deferred-auth posture the
// DACL is the ONLY access boundary, and the trusted-root anchor is
// what keeps a user-writable ancestor from letting a local user plant
// a junction at the target parent. See CR
// spec-004:PRRT_kwDORuAK-s6aoCwa.
const unsafeSocketOverrideEnv = "DEFENSECLAW_ALLOW_UNSAFE_IPC_SOCKET_OVERRIDE"

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
	// spec-004:PRRT_kwDORuAK-s6ankzx and
	// spec-004:PRRT_kwDORuAK-s6aoCwa.
	if err := validateWindowsSocketPathOverride(s.socketPath); err != nil {
		return nil, err
	}

	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, windowsSocketParentDirMode); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	// Refuse a reparse point (junction / symlink) anywhere in the
	// parent chain. A local user who pre-creates a junction at the
	// target `ipc` dir before the daemon starts would otherwise cause
	// os.MkdirAll to reuse the junction and applyBaselineIPCACL to
	// rewrite the DACL of the junction's TARGET — a shared directory
	// the attacker controls. RejectReparseChain walks from dir up to
	// the volume root, so a junction at any ancestor level is refused
	// too. See CR spec-004:PRRT_kwDORuAK-s6aoCwa.
	if err := winpath.RejectReparseChain(dir); err != nil {
		return nil, fmt.Errorf("ipc: reject reparse chain %s: %w", dir, err)
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
//  3. Parent directory basename is "ipc" — cheap shape check.
//  4. Cleaned parent equals `<TrustedProgramData>\<managed-IPC-relative>`
//     (case-insensitive on Windows). Refuses an override that lives
//     under a user-writable ancestor like `C:\Users\<user>\ipc\` —
//     otherwise a local user could plant the socket file (or a
//     junction) there before the daemon starts and have the DACL
//     rewritten under their control.
//
// CI harnesses that legitimately need to scratch-dir the IPC surface
// (e.g. an integration test that binds to a temp path outside the
// trusted root) MUST set the DEFENSECLAW_ALLOW_UNSAFE_IPC_SOCKET_OVERRIDE
// env var to "1"; check (4) then degrades to a warning and only checks
// 1-3 apply. This escape hatch is intentionally named and documented
// as unsafe. See CR spec-004:PRRT_kwDORuAK-s6aoCwa.
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
	parent := filepath.Clean(filepath.Dir(clean))
	if filepath.Base(parent) != "ipc" {
		return fmt.Errorf("ipc: socket path override must live under an 'ipc' directory (got parent %s)", parent)
	}

	// Anchor: parent must equal the trusted managed-IPC root. Bypass
	// only via the explicit test-only env, and only after the three
	// shape checks above already passed.
	if os.Getenv(unsafeSocketOverrideEnv) == "1" {
		return nil
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return fmt.Errorf("ipc: resolve trusted program data root: %w", err)
	}
	if programData == "" {
		return fmt.Errorf("ipc: trusted program data root is empty; refusing to bind IPC surface")
	}
	trustedParent := filepath.Clean(filepath.Join(programData, windowsManagedIPCRelativeDir))
	if !strings.EqualFold(parent, trustedParent) {
		return fmt.Errorf(
			"ipc: socket path override must live under the trusted managed root %q "+
				"(got parent %q); set %s=1 for CI-only overrides",
			trustedParent, parent, unsafeSocketOverrideEnv,
		)
	}
	return nil
}
