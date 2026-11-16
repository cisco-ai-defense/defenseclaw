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

package procboot

import (
	"time"

	"golang.org/x/sys/unix"
)

func fromClock() (int64, bool) {
	real := time.Now().UnixNano()
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return 0, false
	}
	ns := real - boot.Nano()
	if ns <= 0 {
		return 0, false
	}
	return ns / int64(time.Second), true
}
