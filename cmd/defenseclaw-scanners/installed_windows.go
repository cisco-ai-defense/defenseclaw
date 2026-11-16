// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "io"

// runInstalled: Windows runs the runtime embedded in this executable.
func runInstalled([]string, io.Writer, io.Writer) int { return 1 }
