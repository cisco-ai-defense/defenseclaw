// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

// platformManagedGatewayServiceStopped: only a Windows managed gateway is an
// SCM service the hook can query; elsewhere no stop is proven here.
func platformManagedGatewayServiceStopped(string) bool { return false }
