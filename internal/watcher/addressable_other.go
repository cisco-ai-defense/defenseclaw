// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import "path/filepath"

// addressablePath is path: only Windows drops trailing dots and spaces.
func addressablePath(path string) string           { return path }
func addressableStandalonePath(path string) string { return path }

// addressableQuarantinePaths leaves non-Windows paths unchanged.
func addressableQuarantinePaths(path string, roots []string, quarantineRoot string) (string, []string, string) {
	return path, roots, quarantineRoot
}

func physicalAssetName(path string) string { return filepath.Base(path) }

func sameAddressableWatcherPath(left, right string) bool { return false }
