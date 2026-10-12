//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import "path/filepath"

func pathForDataDir(dataDir string) string {
	return filepath.Join(dataDir, StateDirName, FileName)
}

func readStatePathTrusted(string) bool { return true }
