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

package enterprisehooks

import "syscall"

// homeBirth is the creation time of the directory home in nanoseconds, and
// false where the file system keeps none.
func homeBirth(home string) (int64, bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(home, &st); err != nil || (st.Birthtimespec.Sec == 0 && st.Birthtimespec.Nsec == 0) {
		return 0, false
	}
	return st.Birthtimespec.Sec*1_000_000_000 + st.Birthtimespec.Nsec, true
}
