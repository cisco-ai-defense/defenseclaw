// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package acquire

import (
	"fmt"
	"net"
	"os"
)

// authorize refuses any peer whose uid is not on the allow list.
//
// The check is made against the kernel's view of the peer, not against
// anything the peer sends. SO_PEERCRED on Linux and LOCAL_PEERCRED on macOS
// are both filled in by the kernel at connect time and cannot be forged by
// the process on the other end -- which is the entire reason a unix socket
// is the transport here rather than a loopback TCP port, where any local
// process could connect and claim to be anyone.
//
// Socket file permissions are a second layer, not the only one. A mode that
// looks right today can be widened by an unrelated umask change or a
// packaging mistake, and the failure would be silent. This makes it loud.
func (s *Server) authorize(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("acquire: peer arrived on %T, which carries no credentials", conn)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("acquire: peer credentials unavailable: %w", err)
	}
	var (
		peerUID  int
		credsErr error
	)
	controlErr := raw.Control(func(fd uintptr) {
		peerUID, credsErr = peerUIDOf(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("acquire: peer credentials unavailable: %w", controlErr)
	}
	if credsErr != nil {
		return fmt.Errorf("acquire: peer credentials unavailable: %w", credsErr)
	}
	for _, allowed := range s.allowedUIDs() {
		if peerUID == allowed {
			return nil
		}
	}
	return fmt.Errorf("acquire: uid %d is not permitted", peerUID)
}

// allowedUIDs is the configured list, or this process's own uid when none is
// configured. Defaulting to "only me" means a misconfigured helper serves
// nobody rather than everybody.
func (s *Server) allowedUIDs() []int {
	if len(s.config.AllowedUIDs) > 0 {
		return s.config.AllowedUIDs
	}
	return []int{os.Getuid()}
}
