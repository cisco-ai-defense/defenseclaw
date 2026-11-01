// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

// networkShareRoot is "" off Windows: every path is a local file system
// path (an NFS or SMB mount reads like any mounted volume).
func networkShareRoot(string) string { return "" }
