// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsDesktopSurfaceInstalled returns the file that shows connector's
// desktop app is installed for profileHome, or "". A path reached through a
// reparse point is refused.
func windowsDesktopSurfaceInstalled(profileHome, connector string) string {
	programFiles, _ := winpath.TrustedProgramFiles()
	return desktopSurfaceInstalled("windows", profileHome, connector, programFiles, func(candidate string) bool {
		if winpath.RejectReparseChain(candidate) != nil {
			return false
		}
		info, err := os.Lstat(candidate)
		return err == nil && info.Mode().IsRegular()
	})
}
