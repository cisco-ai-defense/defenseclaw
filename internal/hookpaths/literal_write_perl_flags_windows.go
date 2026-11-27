// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

// The Windows reading of sysopen flags (literal_write_perl_flags_wintable.go).
var perlPlatformFlags = perlWindowsFlags

const perlPlatformWriteBits uint64 = perlWindowsWriteBits
