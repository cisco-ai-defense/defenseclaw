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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// bindListenerForOS is the linux + darwin bind block. Applies the
// historical POSIX ACL discipline: dir + socket mode via os.Chmod,
// dir + socket owned by root:staff under managed_enterprise so the
// group-based filesystem filter is real. The Windows sibling in
// server_windows.go uses ACL primitives instead — mode bits + uid/gid
// don't map to Windows DACLs.
//
// Returns the raw net.Listener; the caller wraps it in the codesign
// validating listener.
func (s *Server) bindListenerForOS(ctx context.Context) (net.Listener, error) {
	// Directory permissions track the socket's principal-visibility
	// contract: managed_enterprise creates the parent as root:staff
	// 0750 (traverse for the console user via the staff group;
	// installer normally creates this, we MkdirAll as fallback).
	// Everything else keeps the parent owner-only.
	dir := filepath.Dir(s.socketPath)
	dirMode := os.FileMode(0o700)
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) {
		dirMode = 0o750
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	// MkdirAll respects the process umask (launchd sets 022 or
	// stricter, so a mode-0750 request lands as 0700). Force the
	// intended mode explicitly so the staff group actually gets its
	// traverse bit. Also idempotent when the installer pre-created
	// the dir with a laxer mode.
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("ipc: chmod %s: %w", dir, err)
	}
	// Best-effort chown to root:staff on darwin managed_enterprise.
	// Fails silently on non-root dev runs; a real install runs as
	// root and the chown succeeds. We rely on os.Chown returning
	// EPERM for the unprivileged case and only treat other errors
	// as fatal.
	if runtime.GOOS == "darwin" && managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) && s.staffGID > 0 {
		if err := os.Chown(dir, 0, int(s.staffGID)); err != nil && !os.IsPermission(err) {
			return nil, fmt.Errorf("ipc: chown %s to root:staff: %w", dir, err)
		}
	}

	// Best-effort remove of a stale socket file from a previous run.
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: remove stale socket %s: %w", s.socketPath, err)
	}

	lc := &net.ListenConfig{}
	inner, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", s.socketPath, err)
	}

	if err := os.Chmod(s.socketPath, s.socketMode); err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("ipc: chmod socket %s: %w", s.socketPath, err)
	}
	// Chown the socket itself to root:staff in managed_enterprise so
	// the group-based fs filter is real. Same permission-error
	// tolerance as the dir chown above.
	if runtime.GOOS == "darwin" && managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) && s.staffGID > 0 {
		if err := os.Chown(s.socketPath, 0, int(s.staffGID)); err != nil && !os.IsPermission(err) {
			_ = inner.Close()
			return nil, fmt.Errorf("ipc: chown %s to root:staff: %w", s.socketPath, err)
		}
	}
	return inner, nil
}
