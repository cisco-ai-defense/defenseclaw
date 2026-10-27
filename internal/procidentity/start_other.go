// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package procidentity

import "time"

func startTime(int) (time.Time, bool) { return time.Time{}, false }
