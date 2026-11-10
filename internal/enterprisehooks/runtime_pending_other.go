// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

// WindowsManagedRuntimePendingForSID is the Windows check; it is false here.
func WindowsManagedRuntimePendingForSID(string, string) bool { return false }
