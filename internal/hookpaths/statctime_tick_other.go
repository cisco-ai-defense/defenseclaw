// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hookpaths

import "time"

// filesystemClockNow reports no filesystem clock here, so the fixed guard
// applies (statctime_tick_linux.go).
func filesystemClockNow() (time.Time, bool) { return time.Time{}, false }
