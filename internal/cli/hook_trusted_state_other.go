// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package cli

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"

func trustedNativeHookHome() (string, bool)         { return "", false }
func NativeHookRuntimeNoop() bool                   { return false }
func NativeConnectorHookNoop([]string) bool         { return false }
func enterpriseManagedHookRuntimeNoop(string) bool  { return false }
func enterpriseManagedHookRuntimeForceClosed() bool { return false }
func implicitEnterpriseManagedHook() bool           { return false }
func enterpriseManagedHookRuntimeFailureReason() string {
	return ""
}
func enterpriseManagedHookRuntimeEndpoint(string) (string, string, bool) {
	return "", "", false
}
func enterpriseManagedHookRuntimeConnection(string) (string, string, *string, bool) {
	return "", "", nil, false
}

// applyStandaloneManagedHookTransport: the standalone unix hook runtime does
// not exist on this platform.
func applyStandaloneManagedHookTransport(*hookexec.Options, string) {}

func enterpriseManagedHookRuntimeForeignHookPolicy(string) ([]string, string, string) {
	return nil, "", ""
}
