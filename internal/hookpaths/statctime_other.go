// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package hookpaths

import (
	"os"
	"time"
)

// statChangeTime reports no change time here, so the active-state view is
// read again on every call (statctime_linux.go).
func statChangeTime(os.FileInfo) (time.Time, bool) { return time.Time{}, false }
