//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func fromFD(fd int) (Credentials, error) {
	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Credentials{}, fmt.Errorf("peercred: SO_PEERCRED: %w", err)
	}
	if ucred == nil {
		return Credentials{}, errors.New("peercred: SO_PEERCRED returned no credentials")
	}
	return Credentials{UID: int(ucred.Uid), GID: int(ucred.Gid), PID: int(ucred.Pid)}, nil
}
