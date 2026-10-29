// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package scanner

// rawOpenDirOnce: only macOS answers a guarded folder with EINTR (GAP-1529).
func rawOpenDirOnce(string) error { return nil }
