// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package assetfacts

// onNetworkShare is false off Windows: every path is a local file system path.
func onNetworkShare(string) bool { return false }
