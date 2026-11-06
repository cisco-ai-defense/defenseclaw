// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package processutil

// FileHolders is nil off Windows: no sharing modes hold a file there.
func FileHolders(string) []string { return nil }
