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

package inventory

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// agentBinaryDirs are the folders the hook enumerator looks for agents in
// for home (replaceable in tests).
var agentBinaryDirs = enterprisehooks.UnixAgentSearchDirs

// Only the fixed machine binary directories are known to be system locations.
// An arbitrary PATH hit outside scanned homes may belong to another account.
func systemAgentInstallLocation(path string) bool {
	for _, dir := range enterprisehooks.UnixAgentSearchDirs("") {
		if filepath.IsAbs(dir) && sameInventoryPath(filepath.Dir(path), dir) {
			return true
		}
	}
	return false
}
