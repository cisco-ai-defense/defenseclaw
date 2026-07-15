// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
)

func atomicTransformPathsEqualPlatform(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func atomicTransformLocationsEquivalentPlatform(a, b string) bool {
	if atomicTransformPathsEqualPlatform(a, b) {
		return true
	}
	aInfo, aErr := os.Stat(a)
	bInfo, bErr := os.Stat(b)
	if aErr == nil && bErr == nil && os.SameFile(aInfo, bInfo) {
		return true
	}
	aParent, aParentErr := os.Stat(filepath.Dir(a))
	bParent, bParentErr := os.Stat(filepath.Dir(b))
	return aParentErr == nil && bParentErr == nil &&
		os.SameFile(aParent, bParent) && filepath.Base(a) == filepath.Base(b)
}

func atomicTransformResolveDirectoryPathPlatform(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func atomicTransformValidateDirectoryCaseSemantics(string) error { return nil }

func atomicTransformCanonicalizeExistingLeafPlatform(path string) (string, error) { return path, nil }

func atomicTransformValidateNoReparsePathPlatform(string) error { return nil }
