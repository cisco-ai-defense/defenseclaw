// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "time"

func platformHostIdlePercent(time.Duration) (int, bool) { return 0, false }
