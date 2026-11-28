// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package hookpaths

import "os"

var perlPlatformFlags = [...]perlFlagConstant{}

// perlPlatformWriteBits are the open flag bits beyond the access mode that
// change the path.
const perlPlatformWriteBits = uint64(os.O_CREATE | os.O_TRUNC | os.O_APPEND)
