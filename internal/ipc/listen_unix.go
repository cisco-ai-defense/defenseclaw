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
	"syscall"
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

// chownIfRequested applies ownership when the caller asked for it, and
// then checks that it actually took.
//
// The verification is the point. A permission error has to be
// tolerated so an unprivileged developer run still binds -- but
// tolerating it unconditionally is how a socket silently keeps the
// wrong owner, which is an access filter that looks present and is
// not. That is not hypothetical: a systemd unit whose
// CapabilityBoundingSet omits CAP_CHOWN runs as root and still cannot
// chown, so the socket stays root-owned, the account that was meant
// to reach it cannot, and the service comes up reporting success
// while brokering nothing.
//
// So a failure is forgiven only when the ownership is already what
// was asked for. Anything else is fatal and names the capability,
// because the operator has to change the unit, not the code.
func chownIfRequested(path string, spec ListenSpec) error {
	if spec.OwnerUID < 0 || spec.OwnerGID < 0 {
		return nil
	}
	chownErr := os.Chown(path, spec.OwnerUID, spec.OwnerGID)
	ownerUID, ownerGID, statErr := ownerOf(path)
	if statErr != nil {
		return fmt.Errorf("ipc: stat %s after chown: %w", path, statErr)
	}
	if ownerUID == spec.OwnerUID && ownerGID == spec.OwnerGID {
		return nil
	}
	if chownErr == nil {
		return fmt.Errorf(
			"ipc: chown %s to %d:%d reported success but the path is owned by %d:%d",
			path, spec.OwnerUID, spec.OwnerGID, ownerUID, ownerGID)
	}
	return fmt.Errorf(
		"ipc: %s must be owned by %d:%d for the peer account to reach it, but it is "+
			"owned by %d:%d and chown failed (%w). A root service still needs CAP_CHOWN "+
			"in its CapabilityBoundingSet to change ownership",
		path, spec.OwnerUID, spec.OwnerGID, ownerUID, ownerGID, chownErr)
}

// ownerOf reads the current uid and gid of a path.
func ownerOf(path string) (int, int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("ipc: %s carries no unix ownership", path)
	}
	return int(stat.Uid), int(stat.Gid), nil
}
