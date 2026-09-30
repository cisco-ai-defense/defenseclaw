// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "os"

// unixDesktopSurfaceReason reports connector's desktop app for home as an
// install without a readable version, or returns "". Nothing is executed.
func unixDesktopSurfaceReason(home, connector string) string {
	path := desktopSurfaceInstalled(unixAgentAppBundleGOOS, home, connector, "", func(candidate string) bool {
		info, err := os.Lstat(candidate)
		return err == nil && info.Mode().IsRegular()
	})
	if path == "" {
		return ""
	}
	return UnixAgentUnversionedReasonPrefix + desktopSurfaceReason(path)
}
