// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

// perUserInstallWindowWithoutListener: a refused loopback connect returns at
// once outside Windows, so the call always dials (see the Windows file,
// GAP-1150).
func perUserInstallWindowWithoutListener(Options) bool { return false }
