//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import "path/filepath"

func pathForDataDir(dataDir string) string {
	return filepath.Join(dataDir, StateDirName, FileName)
}

func readStatePathTrusted(string) (bool, error) { return true, nil }
