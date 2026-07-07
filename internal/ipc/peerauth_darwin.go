// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func init() {
	readPeerIdentity = func(fd int, id *peerIdentity) error {
		cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return fmt.Errorf("ipc: peer identity: LOCAL_PEERCRED: %w", err)
		}
		id.UID = cred.Uid
		if cred.Ngroups > 0 {
			id.GID = cred.Groups[0]
		}
		// LOCAL_PEERPID is optional (darwin-only, not always available)
		// but useful for debugging. Failure to read is not fatal.
		if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			id.PID = int32(pid)
		}
		return nil
	}
}
