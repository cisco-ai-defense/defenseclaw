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

import "syscall"

// yieldToHooks lowers the CPU priority of this lifecycle run, and of the
// gateway CLI children it starts, to lifecycleNice; a process already lower
// keeps its value.
func yieldToHooks() {
	if current, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0); err == nil && current >= lifecycleNice {
		return
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, lifecycleNice)
}
