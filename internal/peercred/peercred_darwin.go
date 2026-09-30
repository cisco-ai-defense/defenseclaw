//go:build darwin

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
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Credentials{}, fmt.Errorf("peercred: LOCAL_PEERCRED: %w", err)
	}
	if xucred == nil {
		return Credentials{}, errors.New("peercred: LOCAL_PEERCRED returned no credentials")
	}
	credentials := Credentials{UID: int(xucred.Uid), GID: -1}
	if xucred.Ngroups > 0 {
		credentials.GID = int(xucred.Groups[0])
	}
	if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil && pid > 0 {
		credentials.PID = pid
	}
	return credentials, nil
}
