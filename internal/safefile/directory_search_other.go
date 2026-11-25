// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package safefile

import "golang.org/x/sys/unix"

const directorySearchMode = unix.O_RDONLY
