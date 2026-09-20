// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
)

// ListenSpec describes a local socket to bind with this package's
// hardening discipline.
//
// The discipline is not obvious and was not free -- it refuses a stale
// socket, a reparse point anywhere in the parent chain on Windows, a
// path outside the dedicated directory, and a parent directory mode
// that would let an unprivileged user pre-create a decoy at the socket
// path while the daemon is stopped. Every one of those came out of
// review on spec 004.
//
// It is exported so a second local service cannot get any of that
// subtly wrong by reimplementing it. A privileged sensor helper is the
// first such caller: it holds more authority than the UI IPC server
// does, so it is the last place a second, drifting copy of the bind
// rules belongs.
type ListenSpec struct {
	// Path is the socket path. On Windows it must live under the
	// dedicated IPC directory; an override elsewhere is refused
	// rather than having its DACL rewritten.
	Path string
	// SocketMode is the POSIX mode applied to the socket file.
	// Ignored on Windows, where the DACL is the boundary.
	SocketMode os.FileMode
	// DirMode is the POSIX mode applied to the parent directory.
	// Ignored on Windows.
	DirMode os.FileMode
	// OwnerUID and OwnerGID chown the socket and its parent when both
	// are non-negative and this process can. A permission failure is
	// tolerated so an unprivileged dev run still binds; any other
	// error is fatal. Ignored on Windows.
	OwnerUID int
	OwnerGID int
	// BaseName is the socket filename this caller is permitted to bind.
	// Empty means the UI IPC socket.
	//
	// Windows anchors a bind to the trusted managed IPC directory and, up
	// to now, to a single hard-coded filename. The directory is what
	// carries the security property -- it is DACL-controlled and checked
	// for reparse points -- while the filename only distinguishes one
	// local service from another. A second privileged service in the same
	// directory therefore needs to name itself here rather than borrow an
	// identity that is not its own; sharing one socket file between two
	// different access boundaries would be the actually dangerous option.
	BaseName string
	// GatewayOnly removes the Authenticated Users ACE from the Windows socket
	// DACL. The shared parent keeps the baseline traverse/list ACL so UI IPC
	// clients can still reach their separate socket, while its no-create rule
	// prevents an unprivileged user from planting a replacement socket.
	// Privileged services must set this so only SYSTEM, Administrators, and the
	// exact gateway virtual-service SID can connect. Ignored on Unix, where
	// peer UID authorization is enforced by the accepting service.
	GatewayOnly bool
}

// ListenSecured binds a local socket with the hardening above.
//
// The returned listener is raw: peer authentication, if the caller
// needs it, is the caller's to add on top. Callers that need codesign
// validation wrap it; callers that gate on peer uid check at accept.
func ListenSecured(ctx context.Context, spec ListenSpec) (net.Listener, error) {
	if spec.DirMode == 0 {
		spec.DirMode = 0o700
	}
	if spec.SocketMode == 0 {
		spec.SocketMode = 0o660
	}
	if spec.BaseName == "" {
		spec.BaseName = SocketFileName
	}
	return listenSecuredForOS(ctx, spec)
}

// dirOf is filepath.Dir, named so both platform files read the same.
func dirOf(path string) string { return filepath.Dir(path) }
