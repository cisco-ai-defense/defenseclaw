// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

func trustedNativeHookHome() (string, bool)         { return "", false }
func NativeHookRuntimeNoop() bool                   { return false }
func enterpriseManagedHookRuntimeNoop(string) bool  { return false }
func enterpriseManagedHookRuntimeForceClosed() bool { return false }
func enterpriseManagedHookRuntimeFailureReason() string {
	return ""
}
func enterpriseManagedHookRuntimeEndpoint(string) (string, string, bool) {
	return "", "", false
}
func enterpriseManagedHookRuntimeConnection(string) (string, string, *string, bool) {
	return "", "", nil, false
}
