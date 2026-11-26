// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winpath

import "path/filepath"

// evalLinks is filepath.EvalSymlinks: only Windows has links (junctions)
// that it does not follow.
func evalLinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
