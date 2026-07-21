// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

func trustedNativeHookHome() (string, bool)         { return "", false }
func NativeHookRuntimeNoop() bool                   { return false }
func enterpriseManagedHookRuntimeNoop() bool        { return false }
func enterpriseManagedHookRuntimeForceClosed() bool { return false }
