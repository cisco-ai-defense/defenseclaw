// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scanworker

import (
	"context"
	"net"

	"golang.org/x/sys/unix"
)

type peerKey struct{}

// withPeer records the PID of the socket's peer as this process's PID
// namespace sees it: 0 for a process of another container (the gateway),
// which this namespace cannot name, and -1 when it cannot be read.
func withPeer(ctx context.Context, c net.Conn) context.Context {
	pid := int32(-1)
	if uc, ok := c.(*net.UnixConn); ok {
		if raw, err := uc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
					pid = cred.Pid
				}
			})
		}
	}
	return context.WithValue(ctx, peerKey{}, pid)
}

func peerPID(ctx context.Context) int32 {
	if pid, ok := ctx.Value(peerKey{}).(int32); ok {
		return pid
	}
	return -1
}
