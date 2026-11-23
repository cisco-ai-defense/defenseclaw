// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

// agentBinaryDirs is empty on Windows, where the gateway service cannot list
// the users' bin folders.
var agentBinaryDirs = func(string) []string { return nil }

func systemAgentInstallLocation(path string) bool {
	// Resolve machine roots through Known Folders, never a caller's PATH or
	// account-controlled environment overrides.
	for _, name := range []string{"PROGRAMFILES", "PROGRAMFILES(X86)"} {
		if root, ok := platformDiscoveryVariable(name, ""); ok && pathBelow(root, path) {
			return true
		}
	}
	return false
}
