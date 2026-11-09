// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// osExpandWindowsShortNames is the identity: only a Windows file system has
// 8.3 short names to expand.
func osExpandWindowsShortNames(path string) string { return path }
