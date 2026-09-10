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
)

// listenSecuredForOS is the POSIX bind: mode discipline on the parent
// and the socket, optional ownership, and no stale socket left behind.
func listenSecuredForOS(ctx context.Context, spec ListenSpec) (net.Listener, error) {
	dir := dirOf(spec.Path)
	if err := os.MkdirAll(dir, spec.DirMode); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	// MkdirAll respects the process umask, so a mode-0750 request can
	// land as 0700. Force the intended mode explicitly; this is also
	// idempotent when an installer pre-created the directory laxer
	// than intended.
	if err := os.Chmod(dir, spec.DirMode); err != nil {
		return nil, fmt.Errorf("ipc: chmod %s: %w", dir, err)
	}
	if err := chownIfRequested(dir, spec); err != nil {
		return nil, err
	}
	if err := os.Remove(spec.Path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: remove stale socket %s: %w", spec.Path, err)
	}

	var lc net.ListenConfig
	inner, err := lc.Listen(ctx, "unix", spec.Path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", spec.Path, err)
	}
	if err := os.Chmod(spec.Path, spec.SocketMode); err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("ipc: chmod socket %s: %w", spec.Path, err)
	}
	if err := chownIfRequested(spec.Path, spec); err != nil {
		_ = inner.Close()
		return nil, err
	}
	return inner, nil
}

// chownIfRequested applies ownership when the caller asked for it.
//
// A permission error is tolerated: an unprivileged developer run
// cannot chown and should still bind. Anything else is fatal, because
// a socket that silently kept the wrong owner is a filter that looks
// present and is not.
func chownIfRequested(path string, spec ListenSpec) error {
	if spec.OwnerUID < 0 || spec.OwnerGID < 0 {
		return nil
	}
	if err := os.Chown(path, spec.OwnerUID, spec.OwnerGID); err != nil && !os.IsPermission(err) {
		return fmt.Errorf("ipc: chown %s to %d:%d: %w", path, spec.OwnerUID, spec.OwnerGID, err)
	}
	return nil
}
