// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin && !linux

package hookexec

import "time"

// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = false

func processStartTime(time.Time) (time.Time, bool) { return time.Time{}, false }
