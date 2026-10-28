//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "context"

// lockSharedHookRuntime is a Unix lock (hook_runtime_lock_unix.go): the
// Windows install runs through platformInstall, which never reaches it.
func lockSharedHookRuntime(context.Context, string) (func(), error) { return func() {}, nil }
