// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookruntime

import "io"

func Delegate(string, []string, io.Reader, io.Writer, io.Writer) int {
	return 0
}
