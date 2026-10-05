// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// watchdogRenamedAsideSuffix is what scripts/install.ps1 (Remove-Aside)
// appends to a running binary it replaces: Windows lets a running .exe be
// renamed but not overwritten.
const watchdogRenamedAsideSuffix = ".old-"

// watchdogImageRenamedAside reports whether image is the recorded executable
// renamed aside by an upgrade (<recorded>.old-<yyyyMMddTHHmmssfff>). Windows
// then reports the new name for the running process, so a watchdog left
// running from the previous build failed its identity check: watchdog stop
// and start both refused with "ownership is held but its PID publication is
// not ready" and only a manual Stop-Process freed it (GAP-1833). The start
// identity (process creation time) is checked separately, so a recycled PID
// still never matches.
func watchdogImageRenamedAside(image, recorded string) bool {
	index := strings.LastIndex(image, watchdogRenamedAsideSuffix)
	if index <= 0 || recorded == "" {
		return false
	}
	stamp := image[index+len(watchdogRenamedAsideSuffix):]
	if stamp == "" {
		return false
	}
	for _, r := range stamp {
		if (r < '0' || r > '9') && r != 'T' {
			return false
		}
	}
	return pathidentity.Same(image[:index], recorded)
}
