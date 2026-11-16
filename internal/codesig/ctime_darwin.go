// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package codesig

import "syscall"

func statChangeTime(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }
