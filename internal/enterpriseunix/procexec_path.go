// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import "path/filepath"

// absoluteExecPath keeps an absolute exec path. A relative one, from a
// launch as ./claude or through a relative PATH entry, is relative to the
// working directory the process had at exec time, which this process cannot
// know: the kernel's absolute path of the running image replaces it. When
// that path cannot be read the exec path stays as it was, and the coverage
// checks treat a relative one as unknown.
func absoluteExecPath(path string, image func() (string, error)) string {
	if filepath.IsAbs(path) {
		return path
	}
	if kernel, err := image(); err == nil && filepath.IsAbs(kernel) {
		return filepath.Clean(kernel)
	}
	return path
}
