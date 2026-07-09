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
	"fmt"
	"net"
)

// peerIdentity mirrors the unix shape so cross-platform callers can
// reference the type unconditionally. On Windows the fields stay
// zero because peer-credential-over-UDS is not supported.
type peerIdentity struct {
	PID int32
	UID uint32
	GID uint32
}

// extractPeerIdentity is a stub — the UDS gRPC server is not
// supported on Windows in v1. The Server.Start path refuses to run
// on Windows before this is called; keeping the symbol satisfies
// cross-package build.
func extractPeerIdentity(c net.Conn) (peerIdentity, error) {
	return peerIdentity{}, fmt.Errorf("ipc: peer identity: unsupported on windows")
}

// newValidatingListener is a stub — always returns the inner
// listener. The Server refuses to start on Windows regardless.
func newValidatingListener(inner net.Listener, allowedUIDs []int, logReject func(peerIdentity, string)) net.Listener {
	return inner
}
