// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

// evalLinks is pathEvalSymlinks: only Windows has links that
// filepath.EvalSymlinks does not follow.
func evalLinks(name string) (string, error) { return pathEvalSymlinks(name) }
