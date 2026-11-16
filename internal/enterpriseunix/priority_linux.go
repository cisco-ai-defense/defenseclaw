// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"os"
	"strconv"
	"syscall"
)

// yieldToHooks lowers the CPU priority of this lifecycle run to
// lifecycleNice. Linux keeps a nice value per thread, so every thread of the
// process gets it; threads started later inherit it, as do the gateway CLI
// children the run starts. A thread already lower keeps its value.
func yieldToHooks() {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return
	}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		// The raw getpriority(2) result is 20 - nice.
		if current, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid); err == nil && 20-current >= lifecycleNice {
			continue
		}
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, tid, lifecycleNice)
	}
}
