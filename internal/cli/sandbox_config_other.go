// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// Only the Windows implicit run preflight uses this detector. Other platforms
// keep their existing nested/managed/configuration order.
var sandboxWindowsPersonalConfigPermitted = func() bool { return false }
