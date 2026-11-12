// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package hookexec

import "time"

// platformSuspendClock: no sleep-counting clock is read here; the deadline
// stays on the awake clock.
func platformSuspendClock() (time.Duration, bool) { return 0, false }
