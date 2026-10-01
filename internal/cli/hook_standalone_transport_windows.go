// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"

// applyStandaloneManagedHookTransport is a no-op on Windows: managed hooks
// keep the loopback TCP transport bound to the exact SCM gateway PID.
func applyStandaloneManagedHookTransport(*hookexec.Options, string) {}
