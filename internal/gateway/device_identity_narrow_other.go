// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// narrowDeviceIdentityACL repairs a Windows DACL; doctor --fix keeps the
// mode repair on Unix.
func narrowDeviceIdentityACL(string, string) {}
