// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package managed

// InUnmappedRootUserNamespace: only Linux contains scanners in a user
// namespace.
func InUnmappedRootUserNamespace() bool { return false }
