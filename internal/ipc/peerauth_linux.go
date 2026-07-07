// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ipc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func init() {
	readPeerIdentity = func(fd int, id *peerIdentity) error {
		cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return fmt.Errorf("ipc: peer identity: SO_PEERCRED: %w", err)
		}
		id.PID = cred.Pid
		id.UID = cred.Uid
		id.GID = cred.Gid
		return nil
	}
}
