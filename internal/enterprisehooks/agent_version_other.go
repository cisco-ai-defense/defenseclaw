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

// discoverWindowsAgentVersion is a Windows-only feature — this stub
// exists so the package compiles cross-platform. The macOS
// enumerator (packaging/macos/lib/render-targets.sh) already covers
// the darwin side via `discover_agent_version`; nothing about this
// Go function is invoked on non-Windows OSes. The stub returns
// empty so any accidental non-Windows caller would drop the row,
// which is the safe default.
func discoverWindowsAgentVersion(profileHome, connectorName string) string {
	_ = profileHome
	_ = connectorName
	return ""
}

// windowsAgentVersionExplain matches its Windows counterpart's
// signature so callers can share the same reason-reporting shape
// across platforms. Non-Windows callers always get the "unsupported
// platform" explanation.
func windowsAgentVersionExplain(profileHome, connectorName string) (string, string) {
	_ = profileHome
	_ = connectorName
	return "", "windows agent-version discovery is not compiled on this platform"
}
