// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winpath

import (
	"path/filepath"
	"strings"
)

// ComparisonKey returns path cleaned: off Windows a path has one spelling
// per name, and names are case-sensitive.
func ComparisonKey(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}
