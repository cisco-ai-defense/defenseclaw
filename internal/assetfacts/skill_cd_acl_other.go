// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package assetfacts

// ACL semantics vary by platform. Mode bits alone do not prove entry.
func directoryAccessACLAbsent(string) bool { return false }
