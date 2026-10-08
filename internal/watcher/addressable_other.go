// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

// addressablePath is path: only Windows drops trailing dots and spaces.
func addressablePath(path string) string { return path }
